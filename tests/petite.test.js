import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import {
  PETITE_ENGINE, PETITE_ENGINE_BOUNDARY,
  decompressPetiteBlock, walkPetiteTable,
  supportsPetite, unpackPetite,
} from '../src/core/unpackers/petite.js';
import { parsePE } from '../src/core/pe.js';
import { AnalysisError } from '../src/core/errors.js';

// Vetted sample: UnPETite ENLARGE.EXE (r!sc v1.3, 2000-08-06), itself packed
// with Petite 2.2 levels 1-9. Read-only copy in test-results/fixtures/petite/
// (source: 资料/reverse/t43-petite/ENLARGE.EXE, identical to the archived
// 资料/老旧壳脱壳工具/UnPETite/ENLARGE.EXE).
const FIXTURE = 'ENLARGE.EXE';
const FIXTURE_SHA256 = 'ed3d6a0a80dd6b1fb52b51b04b73f0106c5b929a6a5d65d4f35593eaac7d346a';
const FIXTURE_SIZE = 11264;

// Layer1 decode is byte-identical to an x86 emulation of the sample's own
// unpacking stub (资料/reverse/t43-petite/golden-layer1.bin, captured at the
// stub's first SEH dispatch). Digests are pre-fix_offsets.
const GOLDEN_REGIONS = [
  { rva: 0x1000, size: 0x2342, sha256: 'a1fe95837ee969de9561df3221ead4e52db86d348fa1f18e0782ec73e84c1f37' },
  { rva: 0x4000, size: 0x755, sha256: '946acfc0e2b660eaa13db0b9d5add5dc9260f460d2730a5e1c38a7e356b44082' },
  { rva: 0x21000, size: 0x1ec, sha256: 'e5ed3b8dd300adc3a4940b922b4ad0d47d897f479bdb16e9d1db4f5eb1e9ba53' },
];
// Full rebuilt output (deterministic): fix_offsets applied, imports rebuilt
// with mangled-thunk repair, layer2 window wiped.
const OUTPUT_SHA256 = '53f13c5cf2798551867e9b404b20ca4d1d09fb91f3b30b5cfd3220bd70978b9c';
const OUTPUT_SIZE = 15872;
const OEP_RVA = 0x2fe6;

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
let corpus = null;
try {
  const bytes = await readFile(new URL(`../test-results/fixtures/petite/${FIXTURE}`, import.meta.url));
  assert.equal(bytes.length, FIXTURE_SIZE);
  assert.equal(hash(bytes), FIXTURE_SHA256);
  corpus = new Uint8Array(bytes);
} catch (error) {
  if (error.code !== 'ENOENT' && !(error instanceof assert.AssertionError)) throw error;
}
const needsFixture = () => ({ skip: corpus ? false : `test-results/fixtures/petite/${FIXTURE} missing (copy from 资料/reverse/t43-petite)` });
const failure = (fn, code) => assert.throws(fn, error => error instanceof AnalysisError && (!code || error.code === code));

// MSB-first bit writer: the stub reader consumes byte bit 7 first, exactly 8
// data bits per byte (the hardware sentinel never surfaces as a data bit).
class BitWriter {
  constructor() { this.bytes = []; this.cur = 0; this.n = 0; }
  push(bit) {
    this.cur = (this.cur << 1) | (bit & 1);
    if (++this.n === 8) { this.bytes.push(this.cur); this.cur = 0; this.n = 0; }
  }
  pushMany(...bits) { for (const b of bits) this.push(b); }
  // gamma per the decoder: ecx=1; do { ecx = ecx*2 + bit } while (control 1).
  // The leading 1 of the value is the implicit seed; emit the remaining bits
  // MSB-first, each followed by its control bit, last control 0.
  gamma(value) {
    const width = 32 - Math.clz32(value);
    for (let i = width - 2; i >= 0; i--) {
      this.push((value >>> i) & 1);
      this.push(i === 0 ? 0 : 1);
    }
  }
  build() {
    if (this.n === 0) return Uint8Array.from(this.bytes);
    return Uint8Array.from([...this.bytes, this.cur << (8 - this.n)]);
  }
}

test('engine descriptor and boundary stay honest', () => {
  assert.equal(PETITE_ENGINE.id, 'petite-22-pe32');
  assert.equal(PETITE_ENGINE.outputKind, 'rebuilt-pe');
  assert.equal(PETITE_ENGINE.runtimeVerified, false);
  assert.match(PETITE_ENGINE_BOUNDARY.sample, /ed3d6a0a80dd6b1fb52b51b04b73f0106c5b929a6a5d65d4f35593eaac7d346a/);
  assert.match(PETITE_ENGINE_BOUNDARY.limits, /SEH trampoline/);
});

test('supportsPetite gates on signature plus 2.2 anchor', needsFixture(), () => {
  assert.equal(supportsPetite(corpus), true);
  assert.equal(supportsPetite(new Uint8Array([0x4d, 0x5a, 0, 0])), false);
  assert.equal(supportsPetite(new Uint8Array(64)), false);
  assert.equal(supportsPetite(new Uint8Array(0)), false);
});

test('layer1 decode matches the stub-emulation golden byte for byte', needsFixture(), () => {
  const mem = mapSample(corpus);
  const entries = walkPetiteTable(mem, 0x241b8);
  assert.deepEqual(entries.map(e => e.kind), ['move', 'block', 'block', 'block', 'block', 'terminator']);
  for (const region of GOLDEN_REGIONS) {
    assert.equal(hash(mem.subarray(region.rva, region.rva + region.size)), region.sha256, `rva 0x${region.rva.toString(16)}`);
  }
});

test('full unpack: OEP, imports, mangled-thunk repair, deterministic output', needsFixture(), () => {
  const first = unpackPetite(corpus);
  assert.equal(first.metadata.originalEntryPoint, OEP_RVA);
  assert.equal(first.metadata.variant, '2.2');
  assert.equal(first.metadata.outputKind, 'rebuilt-pe');
  assert.equal(first.metadata.importedModules, 3);
  assert.equal(first.metadata.importedFunctions, 15);
  assert.equal(first.metadata.mangledThunksRepaired, 4);
  assert.equal(first.bytes.length, OUTPUT_SIZE);
  assert.equal(hash(first.bytes), OUTPUT_SHA256);
  assert.equal(hash(unpackPetite(corpus).bytes), OUTPUT_SHA256, 'deterministic');
  const parsed = parsePE(first.bytes);
  assert.deepEqual(parsed.warnings, []);
  assert.deepEqual(parsed.imports.map(m => [m.name, m.functions.length]),
    [['KERNEL32.dll', 12], ['USER32.dll', 2], ['COMDLG32.dll', 1]]);
  assert.deepEqual(parsed.imports[0].functions.slice(0, 3).map(f => f.name),
    ['CreateFileA', 'LoadLibraryA', 'GetCommandLineA']);
  assert.equal(parsed.imports[2].functions[0].name, 'GetOpenFileNameA');
  assert.ok(first.metadata.warnings.includes('single-sample-verified-not-executed'));
  assert.ok(first.metadata.packerEntries.includes('move:1734'));
});

test('decoder: literals XOR with the live remaining-count key', () => {
  // Stream: raw 0xaa; one bit byte (four zero type bits); four payload bytes.
  // The bit reader consumes the bit byte on its first reload, then payloads
  // interleave: literal keys are ebx = 4,3,2,1.
  const src = Uint8Array.from([0xaa, 0x00, 0x11, 0x22, 0x33, 0x44]);
  const out = new Uint8Array(8);
  const r = decompressPetiteBlock(src, out, 0, 5);
  assert.equal(r.endCounter, 0);
  assert.deepEqual([...out.subarray(0, 5)], [0xaa, 0x11 ^ 4, 0x22 ^ 3, 0x33 ^ 2, 0x44 ^ 1]);
  assert.equal(r.consumed, 6);
});

test('decoder: new-offset match with overlap repeats the last byte', () => {
  // Stream: raw 0x41; then a match token: gamma 3 (new offset, x=0 => dist 1),
  // 5 zero offset bits, 2-bit length 1 (+1 threshold extra = 2 total).
  const w = new BitWriter();
  w.push(1); // type: match
  w.gamma(3);
  w.pushMany(0, 0, 0, 0, 0); // dh=5 offset bits -> eax = ~0 = dist 1
  w.pushMany(0, 1); // 2-bit length 1 (+ebp 1)
  const src = new Uint8Array([0x41, ...w.build()]);
  const out = new Uint8Array(8);
  const r = decompressPetiteBlock(src, out, 0, 3);
  assert.equal(r.endCounter, 0);
  assert.deepEqual([...out.subarray(0, 3)], [0x41, 0x41, 0x41], 'overlapping dist-1 copy');
});

test('decoder: reuse path takes the previous offset with a 2-bit length', () => {
  // token1: new offset dist 1 len 2 (as above); token2: gamma 2 (reuse) with
  // 2-bit length 1 -> one more byte from the same dist-1 offset.
  const w = new BitWriter();
  w.push(1); w.gamma(3); w.pushMany(0, 0, 0, 0, 0); w.pushMany(0, 1);
  w.push(1); w.gamma(2); w.pushMany(0, 1);
  const src = new Uint8Array([0x41, ...w.build()]);
  const out = new Uint8Array(8);
  const r = decompressPetiteBlock(src, out, 0, 4);
  assert.equal(r.endCounter, 0);
  assert.deepEqual([...out.subarray(0, 4)], [0x41, 0x41, 0x41, 0x41]);
});

test('decoder: gamma length fallback (2-bit zero) expands', () => {
  // outSize 6: raw 0x41; match with dist 1 (ebp 1), 2-bit length 0 -> length
  // gamma 2 -> l = 4, total 5; ends exactly. The gamma path can never encode
  // below 4 (the decoder's do-while doubles the seed at least once).
  const w = new BitWriter();
  w.push(1); w.gamma(3); w.pushMany(0, 0, 0, 0, 0);
  w.pushMany(0, 0); // 2-bit length zero
  w.gamma(2); // length gamma 2 -> l = 4
  const src = new Uint8Array([0x41, ...w.build()]);
  const out = new Uint8Array(8);
  const r = decompressPetiteBlock(src, out, 0, 6);
  assert.equal(r.endCounter, 0);
  assert.deepEqual([...out.subarray(0, 6)], Array(6).fill(0x41));
});

test('decoder: truncated stream and runaway gamma fail closed', () => {
  const out = new Uint8Array(64);
  failure(() => decompressPetiteBlock(new Uint8Array(0), out, 0, 4), 'truncated-input');
  failure(() => decompressPetiteBlock(new Uint8Array([1]), out, 0, 32), 'truncated-input');
  // All-ones bit stream: gamma keeps continuing until the decode limit.
  failure(() => decompressPetiteBlock(new Uint8Array(64).fill(0xff), out, 0, 8), 'petite-decode-limit');
  failure(() => decompressPetiteBlock(new Uint8Array(8), out, 0, 0), 'output-size-limit');
  failure(() => decompressPetiteBlock(new Uint8Array(8), out, 64, 4), 'output-limit');
});

test('table walk rejects runaway or out-of-range entries', () => {
  assert.equal(walkPetiteTable(new Uint8Array(0x100), 0).length, 1, 'null-only table');
  const bad = new Uint8Array(0x100);
  new DataView(bad.buffer).setUint32(0, 0x80000000 | 64, true); // 64 dwords from end 0x100
  failure(() => walkPetiteTable(bad, 0), 'invalid-petite-table');
  const endless = new Uint8Array(0x1000);
  const view = new DataView(endless.buffer);
  for (let i = 0; i < 80; i++) view.setUint32(i * 16, 0x10, true); // size-0 blocks, no terminator
  failure(() => walkPetiteTable(endless, 0), 'invalid-petite-table');
  failure(() => walkPetiteTable(new Uint8Array(8), 0), 'invalid-petite-table');
});

test('move record stores at the inclusive recorded end (std rep movsd)', () => {
  // Entry {move 2 dwords, srcEnd 0x30, dstEnd 0x38}: stores [0x34,0x38) from
  // [0x2c,0x30), then [0x30,0x34) from [0x28,0x2c).
  const img = new Uint8Array(0x40);
  img.set([9, 9, 9, 9], 0x2c);
  const entry = new DataView(img.buffer);
  entry.setUint32(0x00, 0x80000002, true);
  entry.setUint32(0x04, 0x30, true);
  entry.setUint32(0x08, 0x38, true);
  const entries = walkPetiteTable(img, 0);
  assert.deepEqual(entries.map(e => e.kind), ['move', 'terminator']);
  assert.deepEqual([...img.subarray(0x30, 0x38)], [0, 0, 0, 0, 9, 9, 9, 9]);
});

test('unpack rejects a corrupted 2.2 anchor', needsFixture(), () => {
  const broken = new Uint8Array(corpus);
  // anchor at RVA 0x24068 (EP-0x42+0x68), raw 0x468 in the tail section
  for (let i = 0; i < 4; i++) broken[0x468 + i] ^= 0xff;
  assert.equal(supportsPetite(broken), false);
  failure(() => unpackPetite(broken), 'unsupported-petite-variant');
});

test('unpack rejects a broken entry signature', needsFixture(), () => {
  const broken = new Uint8Array(corpus);
  broken[0x442] = 0x90; broken[0x443] = 0x90; // EP raw 0x442, b8 imm32
  assert.equal(supportsPetite(broken), false);
  failure(() => unpackPetite(broken), 'unsupported-petite-variant');
});

test('unpack rejects a truncated packed file', needsFixture(), () => {
  failure(() => unpackPetite(corpus.subarray(0, 0x2000)), 'truncated-input');
  const torn = new Uint8Array(corpus);
  torn.copyWithin(0x800, 0x1000); // shift: raw content breaks mapping checks
  assert.equal(typeof supportsPetite(torn), 'boolean');
});

// Map the sample like the engine does (headers + sections into a virtual image).
function mapSample(bytes) {
  const peOff = bytes[0x3c] | (bytes[0x3d] << 8) | (bytes[0x3e] << 16) | (bytes[0x3f] << 24);
  const opt = peOff + 24;
  const sizeOfImage = (bytes[opt + 56] | (bytes[opt + 57] << 8) | (bytes[opt + 58] << 16) | (bytes[opt + 59] << 24)) >>> 0;
  const mem = new Uint8Array(sizeOfImage);
  mem.set(bytes.subarray(0, 0x400));
  const nsec = bytes[peOff + 6] | (bytes[peOff + 7] << 8);
  const table = opt + (bytes[peOff + 20] | (bytes[peOff + 21] << 8));
  for (let i = 0; i < nsec; i++) {
    const h = table + i * 40;
    const rva = (bytes[h + 12] | (bytes[h + 13] << 8) | (bytes[h + 14] << 16) | (bytes[h + 15] << 24)) >>> 0;
    const rsz = (bytes[h + 16] | (bytes[h + 17] << 8) | (bytes[h + 18] << 16) | (bytes[h + 19] << 24)) >>> 0;
    const raw = (bytes[h + 20] | (bytes[h + 21] << 8) | (bytes[h + 22] << 16) | (bytes[h + 23] << 24)) >>> 0;
    if (rsz) mem.set(bytes.subarray(raw, raw + rsz), rva);
  }
  return mem;
}
