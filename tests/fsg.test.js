import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fixtures } from '../scripts/fetch-fsg-fixtures.mjs';
import { decompressFsg } from '../src/core/codecs/fsg.js';
import { FSG_ENGINE, parseFsgPE, supportsFsg, unpackFsg } from '../src/core/unpackers/fsg.js';
import { parsePE } from '../src/core/pe.js';
import { AnalysisError } from '../src/core/errors.js';
import { MAX_INPUT, MAX_OUTPUT } from '../src/core/bytes.js';

// Download separately: node scripts/fetch-fsg-fixtures.mjs
// Network-free tests. Missing fixtures are explicit skips, corrupted fixtures fail.
const corpus = new Map();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
for (const fixture of fixtures) {
  try {
    const bytes = await readFile(new URL(`../test-results/fixtures/fsg/${fixture.file}`, import.meta.url));
    assert.equal(bytes.length, fixture.size, fixture.file);
    assert.equal(hash(bytes), fixture.sha256, fixture.file);
    corpus.set(fixture.file, bytes);
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
const needs = (...names) => ({ skip: names.every(name => corpus.has(name)) ? false : 'Run node scripts/fetch-fsg-fixtures.mjs (read-only corpus missing)' });
const failure = (fn, code) => assert.throws(fn, error => error instanceof AnalysisError && (!code || error.code === code));
// Independently published golden images are memory-aligned dumps; inspect their
// section tables locally rather than invoking the FSG reader under test.
function goldenRange(bytes, rva, size) {
  const pe = bytes.readUInt32LE(0x3c), table = pe + 24 + bytes.readUInt16LE(pe + 20);
  for (let i = 0; i < bytes.readUInt16LE(pe + 6); i++) {
    const h = table + i * 40, delta = rva - bytes.readUInt32LE(h + 12);
    if (delta >= 0 && delta + size <= bytes.readUInt32LE(h + 16)) {
      const raw = bytes.readUInt32LE(h + 20) + delta;
      assert.ok(raw + size <= bytes.length);
      return bytes.subarray(raw, raw + size);
    }
  }
  assert.fail('unmapped independent golden range');
}
// Their import directory is a post-run dump: descriptors carry RVA-valued
// fields and the IAT holds resolved addresses, so compare name sets only.
function goldenImports(bytes) {
  const pe = bytes.readUInt32LE(0x3c), table = pe + 24 + bytes.readUInt16LE(pe + 20);
  const count = bytes.readUInt16LE(pe + 6);
  const map = (rva, size) => {
    for (let i = 0; i < count; i++) {
      const h = table + i * 40, delta = rva - bytes.readUInt32LE(h + 12);
      if (delta >= 0 && delta + size <= Math.max(bytes.readUInt32LE(h + 8), bytes.readUInt32LE(h + 16))) {
        const raw = bytes.readUInt32LE(h + 20) + delta;
        assert.ok(raw + size <= bytes.length);
        return raw;
      }
    }
    assert.fail('unmapped independent golden range');
  };
  const cstring = rva => {
    const offset = map(rva, 1);
    let value = '';
    while (offset + value.length < bytes.length && bytes[offset + value.length]) value += String.fromCharCode(bytes[offset + value.length]);
    assert.ok(value.length > 0 && value.length < 512, 'unbounded golden import string');
    return value;
  };
  const groups = new Map();
  const dir = bytes.readUInt32LE(pe + 24 + 96 + 8);
  for (let i = 0; i < 64; i++) {
    const offset = map(dir + i * 20, 20);
    const oft = bytes.readUInt32LE(offset), name = bytes.readUInt32LE(offset + 12), ft = bytes.readUInt32LE(offset + 16);
    if (!oft && !name && !ft) break;
    const dll = cstring(name).toLowerCase();
    const names = new Set(groups.get(dll) ?? []);
    for (let j = 0; j < 4096; j++) {
      const thunk = bytes.readUInt32LE(map((oft || ft) + j * 4, 4));
      if (!thunk) break;
      assert.ok(!(thunk & 0x80000000), 'unexpected golden ordinal import');
      names.add(cstring(thunk + 2));
    }
    groups.set(dll, names);
  }
  return groups;
}
const regions = [
  { rva: 0x1000, source: 5796, size: 258920, consumed: 133630, capacity: 0x40000 },
  { rva: 0x41000, source: 139426, size: 3419, consumed: 1550, capacity: 0x5000 },
  { rva: 0x46000, source: 140976, size: 18344, consumed: 12616, capacity: 0x6000 },
  { rva: 0x4c000, source: 153592, size: 14643, consumed: 4410, capacity: 0x5000 },
];

for (const [version, suffix, parseError] of [['1.31', '131', 'section-overlaps-headers'], ['1.33', '133', 'invalid-pe-header']]) {
  const packedName = `fsg${suffix}.bin`, goldenName = `golden${suffix}.bin`;
  test(`FSG ${version}: real PE, rebuilt imports and all decoded regions equal independent golden`, needs(packedName, goldenName), () => {
    const packed = corpus.get(packedName), golden = corpus.get(goldenName), before = hash(packed);
    // The shared strict parser stays strict. Only the FSG-specific path accepts
    // these historic malformed header layouts after checking the whole stub.
    failure(() => parsePE(packed), parseError);
    const view = parseFsgPE(packed);
    assert.equal(supportsFsg(packed, view), true);
    assert.equal(view.sections.length, 2);
    const result = unpackFsg(packed), pe = parsePE(result.bytes, MAX_OUTPUT);
    assert.ok(result.bytes instanceof Uint8Array);
    assert.equal(result.bytes.length, 314880); // 0x400 headers, four payloads, .rsrc, .idata with TLS
    assert.equal(result.metadata.engine, 'fsg-pe32');
    assert.equal(result.metadata.variant, version);
    assert.equal(result.metadata.outputKind, 'rebuilt-pe');
    assert.equal(result.metadata.runtimeVerified, true);
    assert.equal(result.metadata.importedModules, 11);
    assert.equal(result.metadata.originalEntryPoint, 0x40300);
    assert.equal(result.metadata.originalEntryPoint, golden.readUInt32LE(golden.readUInt32LE(60) + 24 + 16));
    assert.deepEqual(pe.warnings, []);
    assert.equal(pe.entryPointRva, 0x40300);
    // Rebuilt import directory: DLL groups and function-name sets identical to
    // the golden oracle (order-independent). IAT arrays return to 0x430f0..0x43678.
    assert.equal(pe.imports.length, 11);
    assert.equal(pe.imports.reduce((sum, module) => sum + module.functions.length, 0), 343);
    const groups = new Map();
    for (const module of pe.imports) {
      const key = module.name.toLowerCase();
      assert.ok(!module.functions.some(fn => fn.ordinal !== undefined));
      groups.set(key, new Set([...(groups.get(key) ?? []), ...module.functions.map(fn => fn.name)]));
    }
    assert.deepEqual(groups, goldenImports(golden));
    assert.ok(pe.directories.every((d, i) => (i === 1 || i === 2 || i === 9 || i === 12) || (d.rva === 0 && d.size === 0)));
    assert.deepEqual([pe.directories[1].rva, pe.directories[1].size], [0x52000, 12 * 20]);
    assert.deepEqual([pe.directories[12].rva, pe.directories[12].size], [0x430f0, 0x43678 - 0x430f0]);
    assert.deepEqual([pe.directories[2].rva, pe.directories[2].size], [0x51000, 0xca0]);
    assert.deepEqual([pe.directories[9].rva, pe.directories[9].size], [0x53dd0, 24]);
    assert.equal(pe.sizeOfImage, 0x54000);
    assert.equal(pe.sections.length, 6);
    assert.equal(pe.sections[4].name, '.rsrc');
    assert.equal(pe.sections[5].name, '.idata');
    assert.equal(pe.sections[5].rva, 0x52000);
    let compared = 0;
    for (const [i, r] of regions.entries()) {
      const raw = pe.rvaToOffset(r.rva, r.size);
      assert.notEqual(raw, null);
      assert.deepEqual(Buffer.from(result.bytes.subarray(raw, raw + r.size)), goldenRange(golden, r.rva, r.size));
      assert.equal(pe.sections[i].virtualSize, r.capacity);
      const iatStart = i === 1 ? 0x430f0 - r.rva : -1, iatEnd = i === 1 ? 0x43678 - r.rva : -1;
      const gapEnd = result.bytes.subarray(raw + r.size, raw + (iatStart >= 0 ? iatStart : pe.sections[i].rawSize));
      assert.ok(gapEnd.every(value => value === 0));
      if (i === 1) {
        const u32 = offset => result.bytes[offset] | (result.bytes[offset + 1] << 8) | (result.bytes[offset + 2] << 16) | (result.bytes[offset + 3] << 24);
        for (const [offset, value] of [[iatStart, pe.imports[0].functions.length], [0x4319c - r.rva, 4], [0x4361c - r.rva, 22]]) {
          assert.equal(u32(raw + offset + value * 4), 0);
          assert.notEqual(u32(raw + offset), 0);
        }
        assert.ok(result.bytes.subarray(raw + iatEnd, raw + pe.sections[i].rawSize).every(value => value === 0));
      }
      compared += r.size;
    }
    assert.equal(compared, 295326);
    for (const warning of ['relocations-not-restored', 'original-headers-not-preserved', 'section-layout-and-permissions-inferred',
      'runtime-not-verified', 'overlay-not-preserved']) assert.ok(result.metadata.warnings.includes(warning));
    for (const removed of ['analysis-only-not-runnable', 'imports-not-rebuilt', 'data-directories-cleared', 'tls-not-restored']) assert.ok(!result.metadata.warnings.includes(removed));
    assert.equal(result.metadata.resourcesRestored, true);
    assert.equal(result.metadata.tlsRestored, true);
    assert.equal(hash(packed), before);
    const again = unpackFsg(packed);
    assert.deepEqual(again, result);
    result.bytes[0] = 0;
    assert.equal(again.bytes[0], 0x4d);
    assert.equal(packed[0], 0x4d);
    assert.equal(supportsFsg(again.bytes, pe), false);
  });
}

test('codec: real concatenated streams, exact consumption, golden bytes, capacities and subviews', needs('fsg133.bin', 'golden133.bin'), () => {
  const packed = corpus.get('fsg133.bin'), golden = corpus.get('golden133.bin');
  for (const r of regions) {
    const tail = packed.subarray(r.source, 160180);
    const result = decompressFsg(tail, r.capacity);
    assert.equal(result.consumed, r.consumed);
    assert.equal(result.bytes.length, r.size);
    assert.deepEqual(Buffer.from(result.bytes), goldenRange(golden, r.rva, r.size));
    const exact = tail.subarray(0, r.consumed);
    assert.deepEqual(decompressFsg(exact, r.size), result);
    failure(() => decompressFsg(exact, r.size - 1), 'output-limit');
    failure(() => decompressFsg(exact.subarray(0, -1), r.capacity), 'truncated-input');
  }
  const padded = new Uint8Array(packed.length + 20).fill(0xff);
  padded.set(packed, 7);
  assert.deepEqual(unpackFsg(padded.subarray(7, 7 + packed.length)), unpackFsg(packed));
});

test('codec: every truncation of the 1550-byte real stream is rejected', needs('fsg133.bin'), () => {
  const r = regions[1], packed = corpus.get('fsg133.bin');
  for (let size = 0; size < r.consumed; size++) failure(() => decompressFsg(packed.subarray(r.source, r.source + size), r.capacity), 'truncated-input');
});

test('codec: invalid types, caps, missing terminators, backreferences and unbounded gamma', () => {
  for (const value of [null, undefined, [], '', new ArrayBuffer(8)]) failure(() => decompressFsg(value, 100), 'invalid-input');
  for (const cap of [-1, 1.5, NaN, Infinity, MAX_OUTPUT + 1, undefined]) failure(() => decompressFsg(new Uint8Array(), cap), 'invalid-output-limit');
  failure(() => decompressFsg(new Uint8Array(), 10), 'truncated-input');
  failure(() => decompressFsg(Uint8Array.of(65), 0), 'output-limit');
  failure(() => decompressFsg(Uint8Array.of(65), 10), 'truncated-input');
  failure(() => decompressFsg(Uint8Array.of(65, 0xc0, 4), 10), 'invalid-back-reference');
  failure(() => decompressFsg(Uint8Array.of(65, 0x80, 0), 10), 'invalid-back-reference');
  failure(() => decompressFsg(Uint8Array.of(65, 0xbf, ...new Array(16).fill(255)), 10), 'fsg-integer-overflow');
  const huge = new Uint8Array(MAX_INPUT + 1);
  failure(() => decompressFsg(huge, 10), 'input-size-limit');
  failure(() => unpackFsg(huge), 'input-size-limit');
  assert.equal(supportsFsg(huge), false);
});

test('probe is noexcept on malformed input and explicitly excludes unvetted versions', needs('lab18-02.bin'), () => {
  for (const value of [null, undefined, [], '', new Uint8Array(), new Uint8Array(256)]) assert.equal(supportsFsg(value), false);
    assert.equal(supportsFsg(corpus.get('lab18-02.bin')), false);
    assert.deepEqual(FSG_ENGINE.variants, ['1.31', '1.33']);
    assert.equal(FSG_ENGINE.outputKind, 'rebuilt-pe');
});

test('PE/stub/support mutations fail closed without native bounds exceptions', needs('fsg133.bin'), () => {
  const original = corpus.get('fsg133.bin'), view = parseFsgPE(original), ep = view.entryPointOffset;
  const sourceHeader = view.sectionTable + 40, optional = view.optionalOffset;
  const cases = [
    b => b.writeUInt32LE(0xffffffff, 60), b => b.writeUInt32LE(0x20, 60),
    b => b.writeUInt16LE(0x8664, view.peOffset + 4), b => b.writeUInt16LE(97, view.peOffset + 6),
    b => b.writeUInt16LE(0x2002, view.peOffset + 22), b => b.writeUInt16LE(0x20b, optional),
    b => b.writeUInt32LE(1, view.directoryOffset + 14 * 8),
    b => b.writeUInt32LE(97, view.directoryOffset - 4),
    b => b.writeUInt32LE(0x200, optional + 32), b => b.writeUInt32LE(0x1000, optional + 36),
    b => b.writeUInt32LE(0x8001000, optional + 56), b => b.writeUInt32LE(1, optional + 60),
    b => b.writeUInt32LE(0xffffffff, optional + 60), b => b.writeUInt32LE(0xffff0000, optional + 28),
    b => b.writeUInt32LE(0xfffffff0, sourceHeader + 20), b => b.writeUInt32LE(0xffffffff, sourceHeader + 16),
    b => b.writeUInt32LE(0x1000, sourceHeader + 12), b => b.writeUInt32LE(0, sourceHeader + 8),
    b => b.writeUInt32LE(1, view.sectionTable + 16), b => b.writeUInt32LE(512, view.sectionTable + 20),
    b => b.writeUInt32LE(0, ep + 1), b => b.writeUInt32LE(0x400100, ep + 1),
    b => b.writeUInt32LE(0x451000, ep + 1), b => { b[ep + 85] ^= 1; },
    b => b.writeUInt32LE(0x1000000, ep + 163),
    b => b.writeUInt32LE(0x405000, 424), // wrong initial destination
    b => b.writeUInt32LE(0x400010, 428), // stream in headers
    b => b.writeUInt32LE(0x478001, 428), // stream at/after stub
    b => b.writeUInt32LE(0x400fff, 432), // unaligned destination
    b => b.writeUInt32LE(0x401001, 432), // duplicate destination
    b => b.writeUInt32LE(0x451001, 432), // outside destination extent
    b => b.writeUInt32LE(0xffffffff, 420), // bad indirect routine table
    b => b.writeUInt32LE(0x478070, 408), // incorrect bit-reader target
    b => b.writeUInt32LE(0x4780a1, 0x1c0), // import blob destination inside the stub
    b => b.writeUInt32LE(0, 0x1c4), // missing import-walk flag dword
    b => b.writeUInt32LE(0, 0x1c8), // truncated second function-table pointer
    b => { for (let i = 432; i < 512; i += 4) b.writeUInt32LE(0x441001, i); },
  ];
  for (const [i, mutate] of cases.entries()) {
    const bytes = Buffer.from(original); mutate(bytes);
    assert.equal(supportsFsg(bytes), false, `mutation ${i}`);
    failure(() => unpackFsg(bytes));
  }
  assert.equal(supportsFsg(original, { ...view, is64: true }), false);
  assert.equal(supportsFsg(original, { ...view, machine: 0x8664 }), false);
});

test('OEP in virtual zero-fill and malformed compressed data cannot report success', needs('fsg133.bin'), () => {
  const original = corpus.get('fsg133.bin'), pe = parseFsgPE(original);
  const bssOep = Buffer.from(original);
  bssOep.writeInt32LE(0x40f00 - pe.entryPointRva - 167, pe.entryPointOffset + 163);
  assert.equal(supportsFsg(bssOep), true); // structural probe, not a decompression promise
  failure(() => unpackFsg(bssOep), 'invalid-original-entry');
  const badStream = Buffer.from(original);
  badStream[5797] = 0xc0; badStream[5798] = 4;
  failure(() => unpackFsg(badStream), 'invalid-back-reference');
});

test('truncated PE headers, source and stub are rejected; overlay is not decoded', needs('fsg133.bin'), () => {
  const packed = corpus.get('fsg133.bin');
  for (let size = 0; size < 1024; size++) {
    const bytes = packed.subarray(0, size);
    assert.equal(supportsFsg(bytes), false);
    failure(() => unpackFsg(bytes));
  }
  for (const size of [5796, 100000, 158002, 160180, 160350, 160428]) {
    assert.equal(supportsFsg(packed.subarray(0, size)), false);
    failure(() => unpackFsg(packed.subarray(0, size)));
  }
  const appended = Buffer.concat([packed, Buffer.alloc(16384, 0xff)]);
  assert.deepEqual(unpackFsg(appended), unpackFsg(packed));
});

test('1.31 word-list bounds and decoder function pointer are validated', needs('fsg131.bin'), () => {
  const packed = corpus.get('fsg131.bin'), pe = parseFsgPE(packed);
  for (const mutate of [
    b => b.writeUInt32LE(0, pe.entryPointOffset + 17),
    b => b.writeUInt16LE(0, 464),
    b => b.writeUInt16LE(0x403, 464), // same initial destination
    b => b.writeUInt16LE(0x600, 464), // destination outside virtual range
    b => b.fill(1, 464, 512), // no terminator
    b => b.writeUInt32LE(0, 472), // import blob destination zeroed
    b => b.writeUInt32LE(0x4780a1, 472), // import blob destination inside the stub
  ]) {
    const bytes = Buffer.from(packed); mutate(bytes);
    assert.equal(supportsFsg(bytes), false);
    failure(() => unpackFsg(bytes));
  }
});

test('corrupted import blob cannot report rebuilt imports', needs('fsg133.bin'), () => {
  const original = corpus.get('fsg133.bin');
  const compressed = Buffer.from(original);
  compressed[158010] ^= 0xff; // compressed import blob byte: probe-blind, unpack-time failure
  assert.equal(supportsFsg(compressed), true);
  failure(() => unpackFsg(compressed));
  for (const mutate of [
    b => b.writeUInt32LE(0x400101, 0x1c0), // unaligned IAT destination below the image
    b => b.writeUInt32LE(0x4780a0, 0x1c0), // IAT destination inside the packed stub
  ]) {
    const bytes = Buffer.from(original); mutate(bytes);
    assert.equal(supportsFsg(bytes), false);
    failure(() => unpackFsg(bytes));
  }
});

test('deterministic malformed streams terminate within input/output budgets', () => {
  let seed = 0xf59133;
  for (let trial = 0; trial < 512; trial++) {
    const bytes = Uint8Array.from({ length: 1 + trial % 128 }, () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed >>> 24; });
    const before = hash(bytes);
    try {
      const result = decompressFsg(bytes, 4096);
      assert.ok(result.bytes.length <= 4096 && result.consumed <= bytes.length);
    } catch (error) { assert.ok(error instanceof AnalysisError, error.stack); }
    assert.equal(hash(bytes), before);
  }
});
