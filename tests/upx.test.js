import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { parsePE } from '../src/core/pe.js';
import { unpackUpx, supportsUpx, parseUpxInput, UPX_ENGINE } from '../src/core/unpackers/upx.js';
import { AnalysisError } from '../src/core/errors.js';

const root = new URL('../test-results/fixtures/upx/', import.meta.url);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const pins = {
  'lbop20.upx.bin': 'e844ea038a39d448b7a803196f6aa5eaf8697dc48b3305a9b28d544784029158',
  'lab18-01.upx.bin': '2ac6635a26049d354c0c46243f6451e6594b130745a08c5a99e96a64fbbbec0f',
  'lbop20.golden.bin': '5b8cc03b22d3bf8d00e600300ece15359dc10148d474f988b643c5ae863d0163',
  // T44 self-made LZMA1 corpus: packed by the pinned tools/upx/upx.exe 4.2.4
  // with --lzma from the lbop20 golden (its packheader UPX! magic and UPX0/UPX1
  // section names neutralized so the official packer accepts its own output);
  // the official -d run over it is the behavioral oracle below.
  'lzma-424.upx.bin': '946f8839288ecf23d31eb8e3ff843b2b485c44b3038b7a182b053738e428c7fd',
  'lzma-424.official-d.bin': '40b1e82148e546c087000f2198a16f6c365f5271166f2a1b81d62dbe15183a0e',
};
const fixtures = {};
for (const [name, sha] of Object.entries(pins)) {
  try { fixtures[name] = await readFile(new URL(name, root)); assert.equal(hash(fixtures[name]), sha, name); }
  catch (e) { if (e.code !== 'ENOENT') throw e; }
}
const available = (...names) => names.every(name => fixtures[name]) ? false : 'Run node scripts/fetch-upx-fixtures.mjs (pinned static data; never execute samples)';
const source = fixtures['lbop20.upx.bin'];
const code = expected => e => e instanceof AnalysisError && e.code === expected;

test('UPX supports is a noexcept preliminary check', () => {
  for (const bytes of [null, undefined, [], '', new Uint8Array(), new Uint8Array(2048)]) {
    assert.equal(supportsUpx(bytes), false);
    assert.equal(supportsUpx(bytes, {}), false);
  }
  assert.equal(UPX_ENGINE.id, 'upx-pe32-nrv');
  assert.equal(UPX_ENGINE.outputKind, 'analysis-pe');
});

test('UPX exact local SizeOfHeaders compatibility; shared parser remains strict', { skip: available('lbop20.upx.bin') }, () => {
  const before = Buffer.from(source);
  assert.throws(() => parsePE(source), code('section-overlaps-headers'));
  const pe = parseUpxInput(source);
  assert.equal(pe.sizeOfHeaders, 0x400); assert.equal(pe.upxHeaderNormalized, true);
  assert.equal(supportsUpx(source, pe), true); assert.deepEqual(source, before);
  const normal = Buffer.from(source); normal.writeUInt32LE(0x400, pe.optionalOffset + 60);
  assert.equal(supportsUpx(normal, parsePE(normal)), true);
  assert.equal(parseUpxInput(normal).upxHeaderNormalized, undefined);
});

test('UPX real NRV2B: whole .text independently equals unipacker golden, including all fixups',
  { skip: available('lbop20.upx.bin', 'lbop20.golden.bin') }, () => {
    const original = Buffer.from(source), golden = fixtures['lbop20.golden.bin'];
    const { bytes, metadata } = unpackUpx(source), pe = parsePE(bytes);
    const start = pe.rvaToOffset(0x1000, 0xb200);
    assert.notEqual(start, null);
    assert.equal(hash(golden.subarray(0x1000, 0xc200)), 'bc9c6394288d46d38deb5026847a4c3605eb9d6f6973bf490eb27c2cabeaf52b');
    assert.deepEqual(Buffer.from(bytes.subarray(start, start + 0xb200)), golden.subarray(0x1000, 0xc200));
    assert.equal(metadata.originalEntryPoint, 0x1252); assert.equal(pe.entryPointRva, 0x1252);
    assert.equal(metadata.decompressedSize, 93445); assert.equal(metadata.compressedSize, 35651);
    assert.equal(metadata.restoredCalls, 1019); assert.equal(metadata.relocatedPointers, 1676);
    assert.deepEqual(source, original); assert.equal(metadata.outputKind, 'rebuilt-pe'); assert.equal(metadata.runtimeVerified, true);
    assert.deepEqual(pe.warnings, []);
    assert.deepEqual(pe.imports.map(m => [m.name, m.functions.length]), [['KERNEL32.DLL', 63], ['USER32.dll', 1]]);
    // The independent dump has an undersized import directory (40 vs 60 bytes).
    // Use its two parsed descriptors only, not its directory completeness as an oracle.
    const independent = parsePE(golden);
    assert.deepEqual(pe.imports.map(m => m.functions.map(f => f.name ?? f.ordinal)),
      independent.imports.map(m => m.functions.map(f => f.name ?? f.ordinal)));
    for (const m of pe.imports) for (let j = 0; j < m.functions.length + 1; j++) {
      const at = pe.rvaToOffset(m.firstThunk + j * 4, 4); assert.notEqual(at, null);
    }
    // The golden runtime dump keeps the packer's moved .rsrc copy, so restored
    // resource/relocation directory records and their bytes agree with it there;
    // differences beyond the resource extent are the dump's resolved stub thunks.
    assert.deepEqual(metadata.restoredDirectories, { resource: 'restored', relocation: 'restored' });
    assert.deepEqual(pe.directories[2], independent.directories[2]);
    assert.deepEqual(pe.directories[5], independent.directories[5]);
    const resource = pe.rvaToOffset(pe.directories[2].rva, pe.directories[2].size);
    const goldenResource = independent.rvaToOffset(independent.directories[2].rva, independent.directories[2].size);
    assert.deepEqual(Buffer.from(bytes.subarray(resource, resource + pe.directories[2].size)),
      golden.subarray(goldenResource, goldenResource + independent.directories[2].size));
    const relocations = pe.rvaToOffset(pe.directories[5].rva, pe.directories[5].size);
    const goldenRelocations = independent.rvaToOffset(independent.directories[5].rva, independent.directories[5].size);
    assert.deepEqual(Buffer.from(bytes.subarray(relocations, relocations + pe.directories[5].size)),
      golden.subarray(goldenRelocations, goldenRelocations + independent.directories[5].size));
    assert.ok(!metadata.unrestoredMetadata.includes('resources'));
    assert.ok(!metadata.unrestoredMetadata.includes('base-relocation-directory'));
    assert.ok(!metadata.warnings.includes('analysis-only-not-runnable'));
    for (let i = 0; i < 16; i++) if (i !== 1 && i !== 12 && i !== 2 && i !== 5) assert.deepEqual(pe.directories[i], { rva: 0, size: 0 });
    assert.equal(pe.sections.length, 2); assert.equal(pe.sections[0].name, '.unpack');
    assert.equal(pe.sections[1].name, '.imports'); assert.equal(pe.sizeOfImage, 0x1a000);
    assert.equal(pe.overlay.size, 0);
  });

test('UPX second real sample: stripped packheader and renamed sections', { skip: available('lab18-01.upx.bin') }, () => {  const { bytes, metadata } = unpackUpx(fixtures['lab18-01.upx.bin']), pe = parsePE(bytes);
  assert.equal(metadata.originalEntryPoint, 0x154f); assert.equal(pe.entryPointRva, 0x154f);
  assert.equal(metadata.decompressedSize, 29793); assert.equal(metadata.compressedSize, 11712);
  assert.equal(metadata.restoredCalls, 209); assert.equal(metadata.relocatedPointers, 0);
  assert.deepEqual(pe.imports.map(m => [m.name, m.functions.length]), [['KERNEL32.DLL', 42], ['ADVAPI32.dll', 2], ['urlmon.dll', 1]]);
  assert.ok(metadata.warnings.includes('packheader-absent-no-checksum'));
  assert.equal(metadata.outputKind, 'rebuilt-pe');
  // Neither the original header nor the packed tail records resources or
  // relocations for this sample; empty directories are the correct state.
  assert.deepEqual(metadata.restoredDirectories, { resource: 'absent', relocation: 'absent' });
  assert.deepEqual(pe.directories[2], { rva: 0, size: 0 }); assert.deepEqual(pe.directories[5], { rva: 0, size: 0 });
  assert.equal(pe.sections.length, 2);
  assert.deepEqual(pe.warnings, []);
});

test('UPX LZMA1 branch: official 4.2.4 self-made sample unpacks with official-tool agreement',
  { skip: available('lzma-424.upx.bin', 'lzma-424.official-d.bin') }, () => {
    const original = Buffer.from(fixtures['lzma-424.upx.bin']);
    const { bytes, metadata } = unpackUpx(fixtures['lzma-424.upx.bin']), pe = parsePE(bytes);
    assert.equal(metadata.variant, 'PE32 LZMA1 / upx 4.2.4 stub / no filter');
    assert.equal(metadata.originalEntryPoint, 0x1252); assert.equal(pe.entryPointRva, 0x1252);
    assert.equal(metadata.decompressedSize, 173477); assert.equal(metadata.compressedSize, 8778);
    assert.equal(metadata.restoredCalls, 0); assert.equal(metadata.relocatedPointers, 0);
    assert.deepEqual(pe.imports.map(m => [m.name, m.functions.length]), [['KERNEL32.DLL', 63], ['USER32.dll', 1]]);
    const official = parsePE(fixtures['lzma-424.official-d.bin']);
    assert.equal(official.entryPointRva, 0x1252);
    // Honest grading: the original header copy records resource/relocation
    // directories that this 4.2.4 repack of a UPX-dumped input does not carry
    // as auxiliary records, so no rebuilt upgrade is claimed for LZMA yet.
    assert.equal(metadata.outputKind, 'analysis-pe'); assert.equal(metadata.runtimeVerified, false);
    assert.deepEqual(metadata.restoredDirectories, { resource: 'not-restored', relocation: 'not-restored' });
    assert.ok(metadata.warnings.includes('analysis-only-not-runnable'));
    assert.ok(!metadata.warnings.includes('packheader-absent-no-checksum'));
    assert.deepEqual(pe.warnings, []);
    assert.deepEqual(fixtures['lzma-424.upx.bin'], original);
    assert.equal(pe.sections.length, 2);
    assert.equal(pe.overlay.size, 0);
  });

test('UPX LZMA1 rejects corrupted blocks, streams, stub pushes and method lies',
  { skip: available('lzma-424.upx.bin') }, () => {
    const lzma = fixtures['lzma-424.upx.bin'], pe = parseUpxInput(lzma);
    // Identity-level damage: the preliminary check refuses up front.
    const identityChanges = [
      b => { b.writeUInt8(2, 0x3e6); },              // method claims NRV2B, stub stays LZMA
      b => { b.writeUInt8(0x26, 0x3ec); },           // LZMA with a filter is not accepted
    ];
    for (const change of identityChanges) {
      const b = Buffer.from(lzma); change(b);
      assert.equal(supportsUpx(b), false);
      assert.throws(() => unpackUpx(b), AnalysisError);
    }
    // Deep damage past the identity layer: supports stays true, unpack refuses.
    const deepChanges = [
      b => { b[0x400] ^= 1; },                       // block framing header
      b => { b[0x402] ^= 1; },                       // first LZMA range-coder byte
      b => { b[pe.entryPointOffset + 0x21] ^= 1; },  // pushed unpacked size disagrees
      b => { b[pe.entryPointOffset + 0x2b] ^= 1; },  // pushed packed consumption disagrees
      b => { b[0x800] ^= 1; },                       // mid-stream, caught by the Adler gate
    ];
    for (const change of deepChanges) {
      const b = Buffer.from(lzma); change(b);
      assert.equal(supportsUpx(b), true);
      assert.throws(() => unpackUpx(b), AnalysisError);
    }
  });

test('UPX corrupt directory records downgrade to analysis-pe instead of guessing', { skip: available('lbop20.upx.bin') }, () => {
  const pe = parseUpxInput(source), auxRaw = pe.sections[2].rawOffset;
  const changes = [
    ['resources-unrecoverable', b => b.writeUInt32LE(0x1ffff, pe.directoryOffset + 2 * 8)],
    ['resources-unrecoverable', b => b.writeUInt16LE(0x7fff, auxRaw + 14)],
    ['relocations-unrecoverable', b => b.writeUInt32LE(0x400, pe.directoryOffset + 5 * 8 + 4)],
    ['relocations-unrecoverable', b => b.writeUInt32LE(4, pe.directoryOffset + 5 * 8 + 4)],
  ];
  for (const [reason, change] of changes) {
    const b = Buffer.from(source); change(b);
    const { bytes, metadata } = unpackUpx(b), parsed = parsePE(bytes);
    assert.equal(metadata.outputKind, 'analysis-pe');
    assert.ok(metadata.warnings.includes(reason));
    assert.ok(metadata.warnings.includes('analysis-only-not-runnable'));
    assert.deepEqual(metadata.restoredDirectories, { resource: 'not-restored', relocation: 'not-restored' });
    assert.deepEqual(parsed.directories[2], { rva: 0, size: 0 });
    assert.deepEqual(parsed.directories[5], { rva: 0, size: 0 });
    assert.equal(parsed.sections.length, 2); assert.deepEqual(parsed.warnings, []);
  }
});

test('UPX independent output ownership, determinism, exact input subview', { skip: available('lbop20.upx.bin') }, () => {
  const padded = new Uint8Array(source.length + 19); padded.set(source, 7);
  const first = unpackUpx(padded.subarray(7, 7 + source.length)), second = unpackUpx(source);
  assert.deepEqual(first, second); first.bytes[0] = 0;
  assert.equal(second.bytes[0], 0x4d); assert.equal(source[0], 0x4d);
});

test('UPX rejects architectures, unknown decoder/filter/tail/version and LZMA', { skip: available('lbop20.upx.bin') }, () => {
  const pe = parseUpxInput(source), ep = pe.entryPointOffset;
  const changes = [
    b => b.writeUInt16LE(0x8664, pe.peOffset + 4), b => b.writeUInt16LE(0x20b, pe.optionalOffset),
    b => b.writeUInt16LE(b.readUInt16LE(pe.peOffset + 22) | 0x2000, pe.peOffset + 22),
    b => b.writeUInt32LE(0x1000, pe.directoryOffset + 14 * 8),
    b => { b[ep] ^= 1; }, b => { b[ep + 0x50] ^= 1; }, b => { b[ep + 0xe0] ^= 1; },
    b => { b[ep + 0x160] ^= 1; }, b => { b[0x3e4] = 14; }, b => { b[0x3e6] = 14; },
    b => { b[0x3fc] = 0x49; }, b => { b[0x3ff] ^= 1; },
  ];
  for (const change of changes) {
    const b = Buffer.from(source); change(b);
    assert.equal(supportsUpx(b), false); assert.throws(() => unpackUpx(b), AnalysisError);
  }
});

test('UPX rejects malformed sizes, compressed extents, backreferences and fixup counts', { skip: available('lbop20.upx.bin') }, () => {
  const pe = parseUpxInput(source), ep = pe.entryPointOffset, st = pe.sectionTable;
  const changes = [
    b => b.writeUInt32LE(0x2000, pe.optionalOffset + 60),
    b => b.writeUInt32LE(128 * 1024 * 1024 + 1, pe.optionalOffset + 56),
    b => b.writeUInt32LE(0x200, st + 40 + 20), // raw section over real header bytes
    b => b.writeUInt32LE(0x800, st + 40 + 16), // EP outside its raw section
    b => b.writeUInt32LE(0x400, st + 80 + 20), // raw sections overlap
    b => b.writeUInt32LE(0x1000, st + 80 + 12), // virtual sections overlap
    b => b.writeUInt32LE(0x400000, ep + 2), // packed source points at headers
    b => b.writeUInt32LE(0, ep + 8), // destination points at packed section
    b => { b[0x400] ^= 1; }, // Adler mismatch
    b => { b.fill(0, 0x3e0, 0x400); b.fill(0, 0x400, 0x440); }, // no header; bad stream, no checksum shortcut
    b => { b.fill(0, 0x3e0, 0x400); b.writeUInt32LE(0xffffffff, ep + 0xd6); }, // bad filter count
    b => { b[ep + 0x1b8] ^= 1; }, // final OEP jump disagreement
  ];
  for (const change of changes) { const b = Buffer.from(source); change(b); assert.throws(() => unpackUpx(b), AnalysisError); }
  for (const length of [0, 63, 0x3ff, 0x400, ep - 1, ep + 16, source.length - 1]) {
    assert.throws(() => unpackUpx(source.subarray(0, length)), AnalysisError);
  }
  assert.throws(() => unpackUpx(new Uint8Array(64 * 1024 * 1024 + 1)), code('input-size-limit'));
});
