// Petite 2.2 (levels 1-9) static unpacker for PE32.
// The bit-stream grammar, block/move table layout, literal XOR, fix_offsets
// scan/clear semantics and the OEP decryption chain are original clean-room
// findings from static analysis of a real Petite 2.2-packed sample
// (UnPETite ENLARGE.EXE itself, sha256 ed3d6a0a...) cross-checked against a
// full x86 emulation of the sample's own stub (资料/reverse/t43-petite) and
// the published UnPETite ASM notes kept in 资料/reverse/petite/source.
// No third-party code is reproduced; closed-source material stays in 资料/.
import { Bytes, MAX_INPUT, MAX_OUTPUT, matchHex } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';

export const PETITE_ENGINE = Object.freeze({
  id: 'petite-22-pe32', family: 'petite', variants: Object.freeze(['2.2-levels-1-9']),
  outputKind: 'rebuilt-pe', runtimeVerified: false, stage: 'experimental',
});

export const PETITE_ENGINE_BOUNDARY = Object.freeze({
  support: 'Petite 2.2 levels-1..9 PE32 EXE stubs: DIE entry signature b8 imm32 68 imm32 64ff35/648925/669c6050 plus the 2.2 anchor dword [EP-0x42+0x68] == 0x080c78166; all other DIE Petite branches (1.x, 2.1, 2.4, level-0, LZMA variants) are rejected as unsupported',
  sample: 'single vetted sample: UnPETite ENLARGE.EXE r!sc v1.3 (2000-08-06), sha256 ed3d6a0a80dd6b1fb52b51b04b73f0106c5b929a6a5d65d4f35593eaac7d346a, itself packed with Petite 2.2',
  verification: 'layer1 decode (move record + compressed blocks + import preseed) is byte-identical to an x86 emulation of the sample\'s own stub over [0x400,0x23000); OEP decrypt passes the stub rol8 sanity byte and lands on decoded executable content; the rebuilt PE re-parses clean with the full import name table',
  limits: 'original DOS/optional header fields are not recovered (the runtime "header block" table entry is an SEH trampoline, not compressed header data — verified by decode attempt and emulation); section names/layout rebuilt; relocation directory cleared; resources carried from the packed .petite section; never executed',
});

// DIE subset anchor for the 2.2 stub (vendor/die/db/PE/packer_Petite.2.sg).
const EP_SIGNATURE_22 = 'b8........68........64ff35........648925........669c6050';
const ANCHOR_22_VERSION = 0x080c78166 >>> 0;
const MAX_TABLE_ENTRIES = 64;
const MAX_DECODE_STEPS_FACTOR = 8;

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function readHeaders(bytes) {
  requireThat(bytes instanceof Uint8Array, 'invalid-input');
  requireThat(bytes.length > 0 && bytes.length <= MAX_INPUT, 'input-size-limit');
  const input = new Bytes(bytes);
  requireThat(input.u16(0) === 0x5a4d, 'not-pe');
  const peOffset = input.u32(0x3c);
  requireThat(peOffset >= 0x40 && peOffset < 0x400, 'invalid-pe-header');
  requireThat(input.u32(peOffset) === 0x4550, 'not-pe');
  const machine = input.u16(peOffset + 4), count = input.u16(peOffset + 6);
  const optionalOffset = peOffset + 24, optionalSize = input.u16(peOffset + 20);
  requireThat(machine === 0x14c && input.u16(optionalOffset) === 0x10b, 'unsupported-variant');
  requireThat(!(input.u16(peOffset + 22) & 0x2000), 'unsupported-variant');
  requireThat(optionalSize >= 0xe0, 'unsupported-variant');
  input.range(optionalOffset, optionalSize);
  const sectionTable = optionalOffset + optionalSize;
  requireThat(count >= 2 && count <= 16, 'unsupported-petite-layout');
  input.range(sectionTable, count * 40);
  requireThat(input.u32(optionalOffset + 92) === 16, 'unsupported-directories');
  requireThat(!input.u32(optionalOffset + 208) && !input.u32(optionalOffset + 212), 'unsupported-variant');
  const sizeOfHeaders = input.u32(optionalOffset + 60), sizeOfImage = input.u32(optionalOffset + 56);
  const sectionAlignment = input.u32(optionalOffset + 32), fileAlignment = input.u32(optionalOffset + 36);
  requireThat(sectionAlignment === 0x1000 && fileAlignment === 0x200, 'unsupported-alignment');
  requireThat(sizeOfHeaders >= sectionTable + count * 40 && sizeOfHeaders <= bytes.length, 'invalid-header-size');
  requireThat(sizeOfImage > 0 && sizeOfImage <= MAX_OUTPUT && sizeOfImage % sectionAlignment === 0, 'output-size-limit');
  const base = input.u32(optionalOffset + 28);
  requireThat(base % 0x10000 === 0 && base + sizeOfImage <= 0x100000000, 'invalid-image-base');
  const sections = Array.from({ length: count }, (_, i) => {
    const h = sectionTable + i * 40;
    const s = { rva: input.u32(h + 12), virtualSize: input.u32(h + 8), rawSize: input.u32(h + 16), rawOffset: input.u32(h + 20) };
    requireThat(s.rva % sectionAlignment === 0 && s.rva >= align(sizeOfHeaders, sectionAlignment), 'invalid-section-rva');
    requireThat(s.rva + Math.max(s.virtualSize, s.rawSize) <= sizeOfImage, 'invalid-section-rva');
    if (s.rawSize) {
      input.range(s.rawOffset, s.rawSize);
      requireThat(s.rawOffset % fileAlignment === 0, 'unsupported-petite-layout');
    }
    return s;
  });
  const directories = Array.from({ length: 16 }, (_, i) => ({ rva: input.u32(optionalOffset + 96 + i * 8), size: input.u32(optionalOffset + 100 + i * 8) }));
  const headerMapEnd = Math.min(sizeOfHeaders, ...sections.filter((s) => s.rawSize).map((s) => s.rawOffset).concat(sizeOfHeaders));
  const rvaToOffset = (rva, length = 1) => {
    if (!Number.isSafeInteger(rva) || rva < 0 || length < 0) return null;
    if (rva + Math.max(1, length) <= headerMapEnd) return rva;
    for (const s of sections) {
      if (s.rawSize && rva >= s.rva && rva + Math.max(1, length) <= s.rva + s.rawSize) return s.rawOffset + (rva - s.rva);
    }
    return null;
  };
  const entryPointRva = input.u32(optionalOffset + 16);
  return { format: 'PE32', architecture: 'x86', peOffset, optionalOffset, sectionTable, sizeOfHeaders,
    sizeOfImage, fileAlignment, sectionAlignment, imageBase: base, entryPointRva, sections, directories, rvaToOffset,
    warnings: [] };
}

// Validate the 2.2 levels-1..9 identity: DIE entry signature plus the version
// anchor dword inside the packer tail, and locate the layer2/table addresses.
function readPackerLayout(pe, bytes) {
  const epOffset = pe.rvaToOffset(pe.entryPointRva, 26);
  requireThat(epOffset !== null, 'invalid-petite-stub');
  requireThat(matchHex(bytes, epOffset, EP_SIGNATURE_22), 'unsupported-petite-variant');
  const host = pe.sections.find((s) => s.rawSize && pe.entryPointRva >= s.rva && pe.entryPointRva < s.rva + Math.max(s.rawSize, s.virtualSize));
  requireThat(host, 'invalid-petite-stub');
  const tailBase = pe.entryPointRva - 0x42;
  const at = (rva, size) => {
    requireThat(rva >= tailBase && rva + size <= host.rva + host.virtualSize, 'invalid-petite-stub');
    const off = pe.rvaToOffset(rva, size);
    requireThat(off !== null, 'invalid-petite-stub');
    return off;
  };
  const dword = (rva) => { const o = at(rva, 4); return (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0; };
  requireThat(dword(tailBase + 0x68) === ANCHOR_22_VERSION, 'unsupported-petite-variant');
  const packerSehRva = (dword(tailBase + 0x48) - pe.imageBase) >>> 0;
  requireThat(packerSehRva > 0 && packerSehRva + 0x400 < pe.sizeOfImage, 'invalid-petite-stub');
  return { host, tailBase, tableRva: tailBase + 0x1b8, packerSehRva };
}

// Virtual image of the packed file (headers + every mapped section).
function mapImage(pe, bytes) {
  const mem = new Uint8Array(pe.sizeOfImage);
  mem.set(bytes.subarray(0, Math.min(pe.sizeOfHeaders, bytes.length)));
  for (const s of pe.sections) {
    if (s.rawSize) mem.set(bytes.subarray(s.rawOffset, s.rawOffset + s.rawSize), s.rva);
  }
  return mem;
}

const rd32 = (m, r) => (m[r] | (m[r + 1] << 8) | (m[r + 2] << 16) | (m[r + 3] << 24)) >>> 0;
const wr32 = (m, r, v) => { m[r] = v & 255; m[r + 1] = (v >>> 8) & 255; m[r + 2] = (v >>> 16) & 255; m[r + 3] = (v >>> 24) & 255; };

// Petite levels-1..9 block decoder. Grammar mirrors the sample's stub:
// MSB-first bit reader (8 data bits per byte, implicit sentinel), first byte
// copied raw, literals XOR-ed with the live remaining-count low byte, unary
// gamma offsets whose high distance thresholds add extra copy length, 2-bit
// short lengths with a gamma+2 fallback, overlapping forward copies, and a
// signed remaining counter that may legally finish negative.
export function decompressPetiteBlock(source, output, dstOffset, outSize, wrapLength) {
  requireThat(source instanceof Uint8Array && output instanceof Uint8Array, 'invalid-input');
  requireThat(Number.isSafeInteger(outSize) && outSize > 0 && outSize <= MAX_OUTPUT, 'output-size-limit');
  requireThat(Number.isSafeInteger(dstOffset) && dstOffset >= 0 && dstOffset + outSize <= output.length, 'output-limit');
  const wrap = wrapLength ?? output.length;
  let si = 0, di = dstOffset, ebx = outSize | 0;
  const t1 = ebx < 0x10000 ? 0xfffffc60 : ebx < 0x40000 ? 0xfffff980 : 0xfffffb00;
  const t2 = ebx < 0x10000 ? 0xffffc060 : ebx < 0x40000 ? 0xffff8180 : 0xffff8300;
  const dh = ebx < 0x10000 ? 5 : ebx < 0x40000 ? 7 : 8;
  let lastOff = 0, dl = 0, steps = 0;
  const read = () => {
    const candidate = (dl >>> 7) & 1;
    const shifted = (dl << 1) & 0xff;
    if (shifted !== 0) { dl = shifted; return candidate; }
    requireThat(si < source.length, 'truncated-input');
    const by = source[si++];
    dl = ((by << 1) | 1) & 0xff;
    return (by >>> 7) & 1;
  };
  requireThat(source.length > 0, 'truncated-input');
  output[di++] = source[si++];
  ebx = (ebx - 1) | 0;
  while (ebx > 0) {
    requireThat(++steps <= MAX_DECODE_STEPS_FACTOR * (outSize + 64), 'petite-decode-limit');
    if (read() === 0) {
      requireThat(si < source.length, 'truncated-input');
      output[di] = source[si++] ^ (ebx & 0xff);
      di++; ebx = (ebx - 1) | 0;
    } else {
      let ebp = 0, ecx = 1;
      do {
        ecx = ((ecx << 1) | read()) >>> 0;
        requireThat(ecx < 0x80000000, 'petite-decode-limit');
      } while (read() === 1);
      let eax;
      if (ecx >= 3) {
        eax = ecx - 3;
        for (let i = 0; i < dh; i++) eax = ((eax << 1) | read()) >>> 0;
        eax = (~eax) >>> 0;
        ebp += 1 + (eax < t1 ? 1 : 0);
        ebp += eax < t2 ? 1 : 0;
        lastOff = eax;
      } else {
        eax = lastOff;
        ecx = 0;
      }
      let len = read();
      len = (len << 1) | read();
      if (len === 0) {
        let g = 1;
        do {
          g = ((g << 1) | read()) >>> 0;
          requireThat(g < 0x80000000, 'petite-decode-limit');
        } while (read() === 1);
        len = g + 2;
      }
      const total = len + ebp;
      requireThat(total <= outSize + 0x10000, 'petite-decode-limit');
      ebx = (ebx - total) | 0;
      const from = ((di + eax) >>> 0) % wrap;
      requireThat(di + total <= output.length, 'output-limit');
      for (let i = 0; i < total; i++) {
        output[di + i] = output[(from + i) % wrap];
      }
      di += total;
    }
  }
  return { endCounter: ebx | 0, consumed: si };
}

// Walk the packer data table. Move records are descending dword copies where
// the recorded ends are the first (highest) dwords stored — std rep movsd
// stores [edi] then decrements — so n dwords land at
// [dstEnd-4(n-1) .. dstEnd]. Null first dword terminates (static semantics;
// the following "header block" entry is a runtime SEH trampoline, not data).
export function walkPetiteTable(mem, tableRva) {
  requireThat(mem instanceof Uint8Array, 'invalid-input');
  requireThat(Number.isSafeInteger(tableRva) && tableRva >= 0 && tableRva + 16 <= mem.length, 'invalid-petite-table');
  const entries = [];
  let p = tableRva;
  for (;;) {
    requireThat(entries.length < MAX_TABLE_ENTRIES, 'invalid-petite-table');
    const first = rd32(mem, p);
    if (first === 0) { entries.push({ kind: 'terminator', rva: p }); break; }
    if (first & 0x80000000) {
      const n = (first & 0x7fffffff) >>> 0;
      const srcEnd = rd32(mem, p + 4), dstEnd = rd32(mem, p + 8);
      requireThat(n > 0 && n <= (mem.length >>> 2), 'invalid-petite-table');
      requireThat(srcEnd + 4 <= mem.length && dstEnd + 4 <= mem.length, 'invalid-petite-table');
      requireThat(srcEnd - 4 * (n - 1) >= 0 && dstEnd - 4 * (n - 1) >= 0, 'invalid-petite-table');
      for (let k = 0; k < n; k++) {
        const s = srcEnd - 4 * k, d = dstEnd - 4 * k;
        mem[d] = mem[s]; mem[d + 1] = mem[s + 1]; mem[d + 2] = mem[s + 2]; mem[d + 3] = mem[s + 3];
      }
      entries.push({ kind: 'move', dwords: n, srcEnd, dstEnd });
      p += 12;
    } else {
      const size = rd32(mem, p + 4), dst = rd32(mem, p + 8), flag = rd32(mem, p + 0xc);
      requireThat(first > 0 && first < mem.length, 'invalid-petite-table');
      requireThat(size < MAX_OUTPUT && dst + size <= mem.length, 'invalid-petite-table');
      entries.push({ kind: 'block', comp: first, size, dst, flag });
      if (size) decompressPetiteBlock(mem.subarray(first), mem, dst, size, mem.length);
      p += 16;
    }
  }
  return entries;
}

// pet22 init: copy the import thunk pointer block and library names into the
// virtual PE header scratch area before the table walk.
function preseedImports(layout, mem, pe) {
  const tail = layout.tailBase;
  const importDataOffset = rd32(mem, tail);
  requireThat(importDataOffset > 0 && importDataOffset < 0x400 && tail + importDataOffset + 8 < pe.sizeOfImage, 'invalid-petite-stub');
  const src1 = tail + importDataOffset + 8;
  const n1 = mem[tail + 0x83];
  requireThat(n1 > 0 && n1 <= 0x40 && src1 + n1 * 4 <= pe.sizeOfImage, 'invalid-petite-stub');
  mem.set(mem.subarray(src1, src1 + n1 * 4), 0x780);
  const src2 = src1 + n1 * 4 + rd32(mem, tail + 0x9c) - 8;
  const n2 = mem[tail + 0x81];
  requireThat(n2 > 0 && n2 <= 0x40 && src2 + n2 * 4 <= pe.sizeOfImage, 'invalid-petite-stub');
  mem.set(mem.subarray(src2, src2 + n2 * 4), 0x7e8);
  return { libraryNames: 0x7e8, libraryDwords: n2 };
}

// fix_offsets pass: per block flag bit0 selects between scanning decoded code
// for E8/E9/0F8x rel32 fields (subtracting the field's byte offset) and
// zero-filling the tail between decoded size and the declared clear length.
export function fixPetiteOffsets(entries, mem) {
  const sections = [];
  for (const e of entries) {
    if (e.kind !== 'block') continue;
    sections.push({ rva: e.dst, size: e.size });
    if (e.flag & 1) {
      let edx = 0;
      let ebx = (e.size - 6) | 0;
      while (ebx >= 0 && edx < e.size) {
        const op = mem[e.dst + edx];
        if (op === 0xe8 || op === 0xe9) {
          adjustRel32(mem, e.dst + edx + 1, edx);
          edx += 5; ebx = (ebx - 5) | 0;
        } else if (op === 0x0f) {
          const modrm = mem[e.dst + edx + 1];
          if (modrm >= 0x80 && modrm <= 0x8f) {
            adjustRel32(mem, e.dst + edx + 2, edx);
            edx += 6; ebx = (ebx - 6) | 0;
          } else { edx++; ebx = (ebx - 1) | 0; }
        } else { edx++; ebx = (ebx - 1) | 0; }
      }
    } else {
      const total = 4 * (e.flag >>> 3) + ((e.flag >>> 1) & 3);
      requireThat(e.dst + e.size + total <= mem.length, 'invalid-petite-table');
      if (total) mem.fill(0, e.dst + e.size, e.dst + e.size + total);
    }
  }
  return sections;
}

function adjustRel32(mem, at, delta) {
  const v = (mem[at] | (mem[at + 1] << 8) | (mem[at + 2] << 16) | (mem[at + 3] << 24)) | 0;
  const n = (v - delta) | 0;
  mem[at] = n & 255; mem[at + 1] = (n >>> 8) & 255; mem[at + 2] = (n >>> 16) & 255; mem[at + 3] = (n >>> 24) & 255;
}

// Second-layer fields (offsets verified against the 2.2 stub): encrypted OEP,
// mangled import descriptor array RVA, CRC window size/rotation.
export function readPetiteLayer2Fields(mem, sehRva, imageSize) {
  requireThat(sehRva + 0x200 < imageSize, 'invalid-petite-stub');
  const fields = {
    encryptedEp: rd32(mem, sehRva + 0x0f),
    importRva: rd32(mem, sehRva + 0x121),
    mangled: rd32(mem, sehRva + 0x1c0),
    crcSize: rd32(mem, sehRva + 0xa8),
    crcRol: mem[sehRva + 0xd0],
  };
  requireThat(fields.importRva > 0 && fields.importRva + 0x400 < imageSize, 'invalid-petite-stub');
  requireThat(fields.crcSize > 0 && fields.crcSize < 0x10000 && sehRva + 0x13 + fields.crcSize <= imageSize, 'invalid-petite-stub');
  requireThat(fields.crcRol < 32, 'invalid-petite-stub');
  return fields;
}

// crc_2nd_layer: rolling ROL/XOR CRC over the decoded layer2 window. The
// runtime morph mixes TEB fs:[0x1c]/fs:[0x22]; with a NULL environment
// pointer and a PID below 0x10000 — the practical Win32 case — the low morph
// word is the constant 1, reproduced by the zeroed-TEB emulation.
export function petiteLayer2Crc(mem, sehRva, size, rol) {
  let crc = 0;
  for (let edi = size; edi >= 0; edi--) {
    if (((crc >>> 0) & 1) === 0) crc = (crc ^ 1) >>> 0;
    crc = ((crc & 0xffffff00) | (((crc & 0xff) ^ mem[sehRva + 0x13 + edi]) & 0xff)) >>> 0;
    crc = ((crc << rol) | (crc >>> (32 - rol))) >>> 0;
  }
  return crc >>> 0;
}

// decrypt_entrypoint_using_import_table: walk the null-terminated FirstThunk
// RVA array, hint-fix name thunks in place (-2), replay the stub's fake
// mangled-thunk schedule into the ror-3 chain, and recover the OEP RVA.
export function decryptPetiteEntry(mem, fields, sehRva, imageBase, entryRva, imageSize) {
  const crc = petiteLayer2Crc(mem, sehRva, fields.crcSize, fields.crcRol);
  let ep = (fields.encryptedEp ^ crc) >>> 0;
  const pep = (imageBase + entryRva) >>> 0;
  let edx = (pep + 5) >>> 0;
  let ptr = fields.importRva;
  let counter = 0;
  const modules = [];
  let guard = 0;
  for (;;) {
    requireThat(++guard <= 0x40, 'invalid-petite-imports');
    const ft = rd32(mem, ptr);
    if (ft === 0) break;
    requireThat(ft > 0 && ft + 4 <= imageSize, 'invalid-petite-imports');
    let t = ft;
    const thunks = [];
    for (;;) {
      requireThat(thunks.length < 0x4000, 'invalid-petite-imports');
      const eax = rd32(mem, t);
      if (eax === 0) break;
      if ((eax & 0x80000000) === 0) wr32(mem, t, (eax - 2) >>> 0);
      else counter = (counter + 1) | 0;
      thunks.push(eax);
      t += 4;
      counter = (counter - 1) | 0;
      if (counter >= 0) continue;
      if (fields.mangled !== 0x90909090) {
        thunks[thunks.length - 1] = edx >>> 0;
        edx = (edx + 5) >>> 0;
        counter = edx & 7;
      }
    }
    modules.push({ firstThunk: ft, thunks });
    const sectionVa = (pep - 0x42) >>> 0;
    for (const p of thunks) {
      ep = (ep - (sectionVa < p ? 1 : 0)) >>> 0;
      ep = (ep - (p < edx ? 1 : 0)) >>> 0;
      ep = ((ep >>> 3) | (ep << 29)) >>> 0;
    }
    ptr += 4;
  }
  const oepRva = (((pep + 5) + ep) >>> 0) - imageBase >>> 0;
  requireThat((oepRva >>> 24) === 0, 'petite-oep-decrypt-failed');
  requireThat(oepRva > 0 && oepRva < imageSize, 'petite-oep-decrypt-failed');
  return { oepRva, modules };
}

// Mangled thunk recovery: slots holding stub jump VAs (>= imageSize) lost
// their original name RVA. The import name table is a contiguous run of
// NUL-terminated ASCII names inside the import block; walk it end to end,
// then re-assign the entries missing from the surviving thunk values in
// ascending order (array order equals table order).
function repairMangledThunks(mem, modules, imageSize, bounds) {
  const mangled = [];
  const kept = new Set();
  for (const m of modules) {
    for (let i = 0; i < m.thunks.length; i++) {
      const v = m.thunks[i];
      if (v >= imageSize) mangled.push({ module: m, index: i });
      else kept.add(v);
    }
  }
  if (!mangled.length) return 0;
  const sorted = [...kept].sort((a, b) => a - b);
  const first = sorted[0], last = sorted[sorted.length - 1];
  requireThat(first >= bounds.start && last < bounds.end, 'invalid-petite-imports');
  // rewind to the table head: extend one name at a time while the candidate
  // is valid ASCII; a NUL run of 8+ bytes or an invalid candidate marks the
  // boundary before the table (intra-table padding stays below that).
  let head = first;
  let guard = 0;
  for (;;) {
    requireThat(++guard <= 0x1000, 'invalid-petite-imports');
    let p = head - 1;
    while (p >= bounds.start && mem[p] === 0) p--;
    requireThat(p >= bounds.start, 'invalid-petite-imports');
    if (head - 1 - p >= 8) break;
    while (p > bounds.start && mem[p - 1] !== 0) {
      requireThat(mem[p - 1] >= 0x20 && mem[p - 1] < 0x7f, 'invalid-petite-imports');
      p--;
    }
    if (mem[p] < 0x20 || mem[p] >= 0x7f) break;
    head = p;
  }
  // walk forward to the block end, collecting every name start
  const table = [];
  let cur = head;
  guard = 0;
  while (cur < bounds.end) {
    requireThat(++guard <= 0x1000, 'invalid-petite-imports');
    let end = cur;
    while (end < bounds.end && mem[end] !== 0) {
      requireThat(mem[end] >= 0x20 && mem[end] < 0x7f, 'invalid-petite-imports');
      end++;
    }
    requireThat(end > cur && end <= bounds.end, 'invalid-petite-imports');
    table.push(cur);
    if (end >= bounds.end) break;
    let next = end;
    while (next < bounds.end && mem[next] === 0) next++;
    if (next >= bounds.end) break;
    cur = next;
  }
  requireThat(table.includes(first) && table.includes(last), 'invalid-petite-imports');
  const missing = table.filter((e) => !kept.has(e));
  requireThat(missing.length === mangled.length, 'invalid-petite-imports');
  for (const slot of mangled) {
    const nameRva = missing.shift();
    slot.module.thunks[slot.index] = nameRva;
    wr32(mem, slot.module.firstThunk + slot.index * 4, (nameRva - 2) >>> 0);
  }
  return mangled.length;
}

// rebuild_pe: carry the packed header forward, wipe the layer2 window, place
// rebuilt import descriptors (Name+FirstThunk) with copied library names,
// stamp OEP/import directory, rebuild the section table from the recovered
// section list (resources appended from the packed directory, non-compressed
// packed sections kept), clear relocations, align raw sizes to 0x200.
function rebuildOutput(pe, mem, entries, fields, oepRva, modules, preseed) {
  const seh = pe.__petiteSeh;
  mem.fill(0, seh, seh + fields.crcSize);

  const sectionData = entries.filter((e) => e.kind === 'block').map((e) => ({ rva: e.dst, size: e.size }));
  const resRva = pe.directories[2].rva, resSize = pe.directories[2].size;
  if (resRva) {
    const slot = sectionData.find((s) => s.rva >= resRva);
    if (slot) { slot.rva = resRva; slot.size = resSize; }
    else sectionData.push({ rva: resRva, size: resSize });
  }
  for (const s of pe.sections) {
    if (!s.rawSize) continue;
    if (!sectionData.some((d) => d.rva === s.rva)) sectionData.push({ rva: s.rva, size: s.rawSize });
  }

  // library names copied after the reserved descriptor area
  let count = 1;
  while (rd32(mem, fields.importRva + count * 4) !== 0) { count++; requireThat(count < 0x40, 'invalid-petite-imports'); }
  const libDwords = preseed.libraryDwords;
  let scan = fields.importRva + (count + 1) * 0x14;
  let found = -1;
  outer: for (;;) {
    requireThat(scan + (libDwords + 2) * 4 <= mem.length, 'invalid-petite-imports');
    scan += 4;
    for (let j = 0; j <= libDwords; j++) {
      if (rd32(mem, scan + j * 4) !== 0) continue outer;
    }
    found = scan + 4;
    break;
  }
  mem.set(mem.subarray(preseed.libraryNames, preseed.libraryNames + libDwords * 4), found);
  const namesRva = found;

  let nameCursor = namesRva;
  let d = fields.importRva;
  for (const m of modules) {
    wr32(mem, d, 0); wr32(mem, d + 4, 0); wr32(mem, d + 8, 0); wr32(mem, d + 12, nameCursor); wr32(mem, d + 16, m.firstThunk);
    while (mem[nameCursor] !== 0) { nameCursor++; requireThat(nameCursor < mem.length, 'invalid-petite-imports'); }
    nameCursor++;
    d += 20;
  }
  wr32(mem, d, 0); wr32(mem, d + 4, 0); wr32(mem, d + 8, 0); wr32(mem, d + 12, 0); wr32(mem, d + 16, 0);

  const sorted = sectionData.slice().sort((a, b) => a.rva - b.rva);
  const after = sorted.find((s) => s.rva > seh + 0x400);
  if (after) {
    const idx = sorted.indexOf(after);
    if (idx > 0) sorted[idx - 1].size -= fields.crcSize;
  }
  const impSlot = sorted.find((s) => s.rva >= fields.importRva);
  if (impSlot) impSlot.size += libDwords * 4;
  sectionData.sort((a, b) => a.rva - b.rva);

  const header = new Uint8Array(pe.sizeOfHeaders);
  header.set(mem.subarray(0, pe.sizeOfHeaders));
  const opt = pe.peOffset + 0x18;
  const put = (r, v) => wr32(header, r, v >>> 0);
  const put16 = (r, v) => { header[r] = v & 255; header[r + 1] = (v >>> 8) & 255; };
  put(opt + 0x10, oepRva);
  put(opt + 0x68, fields.importRva);
  put(opt + 0x70, 0); put(opt + 0x74, 0);
  put16(pe.peOffset + 6, sectionData.length);
  header.fill(0, pe.sectionTable, Math.min(pe.sectionTable + 0x2000, header.length));
  let raw = pe.sizeOfHeaders;
  const chunks = [];
  for (let i = 0; i < sectionData.length; i++) {
    const s = sectionData[i];
    const next = sectionData[i + 1];
    const vsize = next ? next.rva - s.rva : Math.max(0, pe.sizeOfImage - 0x1000 - s.rva);
    let rawSize = s.size;
    if (rawSize % 0x200) rawSize += 0x200 - (rawSize % 0x200);
    const h = pe.sectionTable + i * 0x28;
    put(h, 0x41 + i);
    put(h + 8, vsize);
    put(h + 12, s.rva);
    put(h + 16, rawSize);
    put(h + 20, raw);
    put(h + 36, 0xe0000060);
    chunks.push({ rva: s.rva, raw, rawSize });
    raw += rawSize;
  }
  put(opt + 0x50, pe.sizeOfImage);

  const total = raw;
  const file = new Uint8Array(total);
  file.set(header, 0);
  for (const c of chunks) {
    if (!c.rawSize) continue;
    file.set(mem.subarray(c.rva, Math.min(c.rva + c.rawSize, mem.length)), c.raw);
  }
  return file;
}

export function supportsPetite(bytes) {
  try {
    const pe = readHeaders(bytes);
    readPackerLayout(pe, bytes);
    return true;
  } catch {
    return false;
  }
}

export function unpackPetite(bytes) {
  const pe = readHeaders(bytes);
  const layout = readPackerLayout(pe, bytes);
  pe.__petiteSeh = layout.packerSehRva;
  const mem = mapImage(pe, bytes);
  const preseed = preseedImports(layout, mem, pe);
  const entries = walkPetiteTable(mem, layout.tableRva);
  const fields = readPetiteLayer2Fields(mem, layout.packerSehRva, pe.sizeOfImage);
  const sections = fixPetiteOffsets(entries, mem);
  const { oepRva, modules } = decryptPetiteEntry(mem, fields, layout.packerSehRva, pe.imageBase, pe.entryPointRva, pe.sizeOfImage);
  const importBlock = entries.find((e) => e.kind === 'block' && fields.importRva >= e.dst && fields.importRva < e.dst + e.size);
  requireThat(importBlock, 'invalid-petite-imports');
  const repaired = repairMangledThunks(mem, modules, pe.sizeOfImage, { start: importBlock.dst, end: importBlock.dst + importBlock.size });
  const file = rebuildOutput(pe, mem, entries, fields, oepRva, modules, preseed);

  const validated = parsePE(file, MAX_OUTPUT);
  requireThat(validated.warnings.length === 0 && validated.entryPointOffset !== null, 'output-validation-failed');
  const importedFunctions = modules.reduce((acc, m) => acc + m.thunks.length, 0);
  requireThat(validated.imports.length === modules.length && validated.imports.every((m, i) =>
    m.functions.length === modules[i].thunks.length), 'output-validation-failed');

  return { bytes: file, metadata: {
    engine: PETITE_ENGINE.id, variant: '2.2', outputKind: 'rebuilt-pe', runtimeVerified: false,
    originalEntryPoint: oepRva,
    importedModules: modules.length,
    importedFunctions,
    mangledThunksRepaired: repaired,
    layer1Sections: sections.map((s) => `0x${s.rva.toString(16)}+0x${s.size.toString(16)}`),
    packerEntries: entries.map((e) => e.kind === 'move' ? `move:${e.dwords}` : e.kind === 'block' ? `block:0x${e.comp.toString(16)}->0x${e.dst.toString(16)}` : 'terminator'),
    warnings: [
      'original-header-fields-not-recovered',
      'section-names-and-layout-rebuilt',
      'relocations-cleared',
      'single-sample-verified-not-executed',
      'petite-2-1-and-level-0-variants-rejected',
    ],
  } };
}
