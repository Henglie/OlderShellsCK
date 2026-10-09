import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { AnalysisError } from '../src/core/errors.js';
import { parsePE } from '../src/core/pe.js';
import { analyze, unpack } from '../src/core/index.js';
import { supportsMpress, unpackMpress, restoreCalls } from '../src/core/unpackers/mpress.js';

// Optional research data; never execute it or require a network in tests.
// Fetch explicitly: node scripts/fetch-fixtures.mjs
// unipacker/unipacker@160baa9447c91d53b75e5e108b196d389fa0b06e
// Sample/MPRESS/UnPackMe32_MPRESS.exe
const fixtureUrl = new URL('../test-results/fixtures/mpress.exe', import.meta.url);
const expectedSha256 = '218d5569194ee018b354c9f717047ae2dac5d6130cdf81eb24f0a9b370600136';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const put16 = (bytes, offset, value) => view(bytes).setUint16(offset, value, true);
const put32 = (bytes, offset, value) => view(bytes).setUint32(offset, value, true);
const coded = code => error => error instanceof AnalysisError && (!code || error.code === code);
let fixture;
try { fixture = new Uint8Array(await readFile(fixtureUrl)); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
const optional = { skip: fixture ? false : 'Missing test-results/fixtures/mpress.exe; run node scripts/fetch-fixtures.mjs (static data only).' };
function input() {
  assert.equal(hash(fixture), expectedSha256, 'fixture hash mismatch; do not bless a different binary');
  return fixture.slice();
}

test('CALL/JMP restoration has hand-calculated operands and preserves the reserved final page', () => {
  const bytes = new Uint8Array(0x1020);
  bytes[0] = 0xe8; put32(bytes, 1, 10); // target 10 - operand position 1 = 9
  bytes[5] = 0xe9; put32(bytes, 6, -3); // -3 + operand 6 + limit 32 - operand 6 = 29
  bytes[10] = 0xe8; put32(bytes, 11, 32); // limit is excluded
  bytes[15] = 0xe9; put32(bytes, 16, -17); // outside backward range
  bytes[32] = 0xe8; put32(bytes, 33, 1);
  const tail = bytes.slice(32);
  restoreCalls(bytes);
  assert.equal(view(bytes).getInt32(1, true), 9); assert.equal(view(bytes).getInt32(6, true), 29);
  assert.equal(view(bytes).getInt32(11, true), 32); assert.equal(view(bytes).getInt32(16, true), -17);
  assert.deepEqual(bytes.slice(32), tail);
  for (const length of [0, 1, 0x1000]) assert.doesNotThrow(() => restoreCalls(new Uint8Array(length)));
});

test('real MPRESS: independent golden code, OEP, four modules and rebuilt import consistency', optional, () => {
  const bytes = input(), pe = parsePE(bytes);
  assert.equal(bytes.length, 8192); assert.equal(pe.entryPointRva, 0x7112);
  assert.ok(supportsMpress(bytes, pe));
  const result = unpackMpress(bytes), rebuilt = parsePE(result.bytes);
  assert.equal(result.metadata.originalEntryPoint, 0x1110); assert.equal(rebuilt.entryPointRva, 0x1110);
  assert.equal(result.metadata.importedModules, 4); assert.equal(result.metadata.outputKind, 'rebuilt-pe');
  assert.equal(result.metadata.runtimeVerified, true);
  assert.deepEqual(rebuilt.warnings, []);
  assert.deepEqual(rebuilt.imports.map(module => module.name.toLowerCase()), ['comctl32.dll', 'kernel32.dll', 'msvcrt.dll', 'user32.dll']);
  // Independent golden also documented in tests/lzmat.test.js, not this unpacker's output.
  // Tests/UnpackedSample/MPRESS/unpacked_UnPackMe32_MPRESS.exe [0x1000,0x102b)
  // SHA-256 54fdca0f5eade04eaf3e71e9f39aad7dfe22b5fe3a2b5ca7fadf86c5e341f432
  const golden = Uint8Array.from(Buffer.from('5589e583ec08a160514000c9ffe066905589e583ec08a154514000c9ffe066905589e55383ec34c7042450', 'hex'));
  const code = rebuilt.rvaToOffset(0x1000, golden.length);
  assert.notEqual(code, null); assert.deepEqual(result.bytes.subarray(code, code + golden.length), golden);
  const output = view(result.bytes), descriptors = rebuilt.rvaToOffset(rebuilt.directories[1].rva, 100);
  assert.notEqual(descriptors, null);
  for (const [index, module] of rebuilt.imports.entries()) {
    const ilt = rebuilt.rvaToOffset(output.getUint32(descriptors + index * 20, true), (module.functions.length + 1) * 4);
    const iat = rebuilt.rvaToOffset(module.firstThunk, (module.functions.length + 1) * 4);
    assert.notEqual(ilt, null); assert.notEqual(iat, null); assert.ok(module.functions.length > 0);
    assert.deepEqual(result.bytes.subarray(iat, iat + (module.functions.length + 1) * 4), result.bytes.subarray(ilt, ilt + (module.functions.length + 1) * 4));
    assert.equal(output.getUint32(iat + module.functions.length * 4, true), 0);
  }
  assert.equal(hash(bytes), expectedSha256);
});

test('real MPRESS: repeated calls are deterministic, isolated, and public API reports the output', optional, async () => {
  const bytes = input(), storage = new Uint8Array(bytes.length + 23); storage.set(bytes, 11);
  const original = storage.slice(), exactView = storage.subarray(11, 11 + bytes.length);
  const first = unpackMpress(exactView), second = unpackMpress(exactView);
  assert.deepEqual(first.bytes, second.bytes); assert.deepEqual(first.metadata, second.metadata);
  first.bytes.fill(0);
  assert.equal(hash(second.bytes), hash(unpackMpress(exactView).bytes));
  assert.deepEqual(storage, original);
  const report = await analyze(exactView);
  assert.ok(report.detections.some(hit => hit.family === 'MPRESS'));
  assert.deepEqual(report.candidates.map(candidate => candidate.id), ['mpress-pe32-lzmat']);
  const result = await unpack(exactView, 'mpress-pe32-lzmat', '../../unsafe:name.exe');
  assert.equal(result.name, 'unsafe_name.exe.unpacked.exe');
  assert.equal(result.report.file.sha256, hash(result.bytes)); assert.equal(result.report.pe.entryPointRva, 0x1110);
  assert.deepEqual(result.report.candidates, []); assert.deepEqual(storage, original);
});

test('REGRESSION: real MPRESS DOS-stub detection finds the version in its fixed search window', optional, async () => {
  const bytes = input(), report = await analyze(bytes);
  const hit = report.detections.find(hit => hit.family === 'MPRESS');
  assert.equal(hit?.version.trim(), '2.19', JSON.stringify({ hit, dos: Buffer.from(bytes.subarray(0x2e, 0x3b)).toString('latin1'), versionWindow: Buffer.from(bytes.subarray(0x1f0, 0x200)).toString('hex') }));
});

test('real MPRESS: unknown stubs, DLL, .NET, TLS and PE32+ are refused without input mutation', optional, () => {
  const pe = parsePE(input()), ep = pe.entryPointOffset;
  const cases = [
    ['unknown stub', bytes => put32(bytes, ep + 8, 0x29e), 'unsupported-variant'],
    ['unknown fix stub', bytes => put32(bytes, ep + 0x2a1, 0x1000 - pe.entryPointRva - 0x2a5), 'unsupported-fix-stub'],
    ['corrupt opcode', bytes => { bytes[ep] = 0; }, 'unsupported-variant'],
    ['DLL', bytes => put16(bytes, pe.peOffset + 22, view(bytes).getUint16(pe.peOffset + 22, true) | 0x2000), 'unsupported-variant'],
    ['.NET', bytes => put32(bytes, pe.directoryOffset + 14 * 8, 0x1000), 'unsupported-variant'],
    ['TLS', bytes => { put32(bytes, pe.directoryOffset + 9 * 8, 0x1000); put32(bytes, pe.directoryOffset + 9 * 8 + 4, 24); }, 'unsupported-tls'],
    ['PE32+', bytes => {
      bytes.copyWithin(pe.sectionTable + 16, pe.sectionTable, pe.sectionTable + pe.sections.length * 40);
      bytes.copyWithin(pe.directoryOffset + 16, pe.directoryOffset, pe.directoryOffset + 128);
      put16(bytes, pe.peOffset + 20, 240); put16(bytes, pe.peOffset + 4, 0x8664);
      put16(bytes, pe.optionalOffset, 0x20b); put32(bytes, pe.optionalOffset + 108, 16);
      assert.equal(parsePE(bytes).is64, true);
    }, 'unsupported-variant'],
  ];
  for (const [label, mutate, code] of cases) {
    const bytes = input(); mutate(bytes); const original = bytes.slice();
    assert.throws(() => unpackMpress(bytes), coded(code), label); assert.deepEqual(bytes, original);
  }
});

test('real MPRESS: malformed packed lengths, pointers and alignments fail within bounds', optional, () => {
  const pe = parsePE(input()), ep = pe.entryPointOffset, packed = pe.sections[0];
  const cases = [
    ['zero capacity', bytes => put16(bytes, packed.rawOffset, 0), 'output-size-limit'],
    ['oversized capacity', bytes => put16(bytes, packed.rawOffset, 0xffff), 'output-size-limit'],
    ['zero stream', bytes => put32(bytes, packed.rawOffset + 2, 0), 'truncated-packed-data'],
    ['oversized stream', bytes => put32(bytes, packed.rawOffset + 2, 0xffffffff), 'truncated-packed-data'],
    ['complete short stream', bytes => put32(bytes, packed.rawOffset + 2, 1), 'decoded-size-mismatch'],
    ['packed pointer', bytes => put32(bytes, ep + 0x2a5, 0x7fffffff), 'invalid-packed-section'],
    ['fix pointer', bytes => put32(bytes, ep + 0x2a1, 0x7fffffff), 'truncated-input'],
    ['unaligned file', bytes => put32(bytes, pe.optionalOffset + 36, 0x201), 'invalid-alignment'],
    ['small section alignment', bytes => put32(bytes, pe.optionalOffset + 32, 0x200), 'unsupported-alignment'],
  ];
  for (const [label, mutate, code] of cases) {
    const bytes = input(); mutate(bytes); const original = bytes.slice();
    assert.throws(() => unpackMpress(bytes), coded(code), label); assert.deepEqual(bytes, original);
  }
});

test('REGRESSION: MPRESS must refuse unvalidated nonzero relocation data', optional, () => {
  const bytes = input(), pe = parsePE(bytes);
  // RVA is mapped, but these are machine-code bytes, not IMAGE_BASE_RELOCATION.
  put32(bytes, pe.entryPointOffset + 0x2a9, 0x1000);
  put32(bytes, pe.entryPointOffset + 0x2b1, 8);
  assert.throws(() => unpackMpress(bytes), coded(), 'mapping a directory is not validating its block structure');
});

test('real MPRESS: overlay/signature removal is explicit in output metadata', optional, () => {
  const original = input(), pe = parsePE(original);
  const bytes = new Uint8Array(original.length + 16); bytes.set(original);
  put32(bytes, pe.directoryOffset + 4 * 8, original.length);
  put32(bytes, pe.directoryOffset + 4 * 8 + 4, 16);
  const result = unpackMpress(bytes), rebuilt = parsePE(result.bytes);
  assert.ok(result.metadata.warnings.includes('overlay-not-preserved'));
  assert.ok(result.metadata.warnings.includes('signature-removed'));
  assert.deepEqual(rebuilt.directories[4], { rva: 0, size: 0 }); assert.equal(rebuilt.overlay.size, 0);
});
