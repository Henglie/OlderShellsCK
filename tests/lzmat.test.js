import test from 'node:test';
import assert from 'node:assert/strict';
import { decompressLzmat } from '../src/core/codecs/lzmat.js';
import { AnalysisError } from '../src/core/errors.js';

const hex = text => Uint8Array.from(Buffer.from(text.replace(/\s/g, ''), 'hex'));
const join = (...parts) => {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let pos = 0;
  for (const part of parts) { result.set(part, pos); pos += part.length; }
  return result;
};
const fails = (input, limit, code) => assert.throws(
  () => decompressLzmat(input, limit),
  error => error instanceof AnalysisError && error.code === code,
);

// External golden pair, fetched as data only; no binary was executed.
// Repository: https://github.com/unipacker/unipacker
// Commit: 160baa9447c91d53b75e5e108b196d389fa0b06e
// Sample/MPRESS/UnPackMe32_MPRESS.exe [0x206, 0x226)
//   Git blob: 164e506614f19d00db79e7ce470f8263317a8a5e
//   SHA-256: 218d5569194ee018b354c9f717047ae2dac5d6130cdf81eb24f0a9b370600136
// Tests/UnpackedSample/MPRESS/unpacked_UnPackMe32_MPRESS.exe [0x1000, 0x102b)
//   Git blob: 527b51f5cbcc3edd66a672494d88bc730c9be8c0
//   SHA-256: 54fdca0f5eade04eaf3e71e9f39aad7dfe22b5fe3a2b5ca7fadf86c5e341f432
// Expected bytes come from the independently unpacked file, not this decoder.
// This prefix ends before CALL/JMP filtering and import repair affect bytes.
// Full packed extent: [0x206, 0xca9), capacity 0x6000, EP RVA 0x7112,
// MPRESS 2.19 string and 0x29f LZMAT stub signature. Full-stream decoded
// length observed: 0x6000; SHA-256 (before PE fixups):
// e30aab562f7d29c5eda8a4508d7283d11eec9473bc62f0f1ad78c7e1f7e25d1d
const packedGolden = hex('550089e583ec08a16051014000c9ffe066901e0444e5815383ec34c704002450');
const unpackedGolden = hex('5589e583ec08a160514000c9ffe066905589e583ec08a154514000c9ffe066905589e55383ec34c7042450');

test('real MPRESS compressed prefix matches independent unpacked bytes', () => {
  assert.deepEqual(decompressLzmat(packedGolden, 0x6000), unpackedGolden);
  assert.deepEqual(decompressLzmat(packedGolden, unpackedGolden.length), unpackedGolden);
  fails(packedGolden, unpackedGolden.length - 1, 'output-limit');
});

test('literals, zero bytes, multiple tags, and actual owned output length', () => {
  const input = hex('00 00 0102030405060708 00 090a');
  const original = input.slice();
  const result = decompressLzmat(input, 128 * 1024 * 1024);
  assert.deepEqual(result, hex('000102030405060708090a'));
  assert.equal(result.buffer.byteLength, 11);
  result[0] = 0xff;
  assert.deepEqual(input, original);
});

test('input-end termination matches RetDec, including unused tags/nibbles', () => {
  for (const stream of ['41', '4100', '4180', '41ff']) {
    assert.deepEqual(decompressLzmat(hex(stream), 10), hex('41'));
  }
  // Distance 1, length 3, final high nibble ignored even if nonzero.
  assert.deepEqual(decompressLzmat(hex('418000f0'), 20), hex('41414141'));
  // A complete final token can end in the high nibble with no lookahead.
  assert.deepEqual(decompressLzmat(hex('41c0000000'), 20), hex('41414141414141'));
});

test('overlapping matches and literals starting at a high nibble', () => {
  assert.deepEqual(decompressLzmat(hex('41800005'), 9), new Uint8Array(9).fill(0x41));
  assert.deepEqual(decompressLzmat(hex('4180002004'), 20), hex('4141414142'));
  // First two literals AB; tag bit 6 then copies ABABA (distance 2).
  assert.deepEqual(decompressLzmat(hex('4140420202'), 20), hex('41424142414241'));
});

test('all three match-length encodings and their boundary lengths', () => {
  for (const [stream, length] of [
    ['41800000', 3],
    ['4180000e', 17],
    ['4180000f00', 18],
    ['418000ef0f', 272],
    ['418000ff0f0000', 273],
    ['418000ffef ff0f', 65807],
  ]) {
    assert.deepEqual(decompressLzmat(hex(stream), length + 1), new Uint8Array(length + 1).fill(0x41));
    fails(hex(stream), length, 'output-limit');
  }
});

// Only emit literal tags and append a hand-calculated match. This helper does
// not encode distances/lengths or reproduce any decompression decisions.
function literalThenMatch(history, match) {
  const packed = [history[0]];
  for (let i = 1; i < history.length;) {
    packed.push(0);
    for (let j = 0; j < 8 && i < history.length; j++) packed.push(history[i++]);
  }
  const used = (history.length - 1) % 8;
  if (!used) packed.push(0x80);
  else packed[packed.length - used - 1] = 0x80 >>> used;
  packed.push(...hex(match));
  return Uint8Array.from(packed);
}

test('distance widths, both sides of 0x881, and maximum distance', () => {
  // output position, distance, on-wire distance plus length-3 nibble.
  // Early distances use 1 mode bit; at 0x881 they use 2 mode bits.
  for (const [position, distance, wire] of [
    [129, 128, 'fe00'],
    [129, 129, '0100'],
    [0x880, 0x880, 'ff0f'],
    [0x881, 64, 'fc00'],
    [0x881, 65, '0100'],
    [0x881, 0x440, 'fd0f'],
    [0x881, 0x441, '020000'],
    [0x4441, 0x4440, 'feff00'],
    [0x4441, 0x4441, '030000'],
    [0x44441, 0x44440, 'ffff0f'],
  ]) {
    const history = Uint8Array.from({ length: position }, (_, i) => (i * 29) ^ (i >>> 8));
    // Distinct source marker makes accidental adjacent/off-by-one reads fail.
    history.set(hex('5a31c7'), position - distance);
    const stream = literalThenMatch(history, wire);
    const expected = join(history, hex('5a31c7'));
    assert.deepEqual(decompressLzmat(stream, expected.length), expected, `${position}/${distance}`);
    fails(stream, expected.length - 1, 'output-limit');
  }
});

test('verbatim escape: both alignments, high count bits, shifted tag and continuation', () => {
  for (const [header, prefix, length] of [
    ['418000ffffff0f', '41', 32],
    ['418001f0ffffff', '41', 32],
    ['418c08ffffff0f', '41', 2176],
    ['418301f1ffffff', '41', 4152],
    ['41404200ffffff0f', '4142', 32],
  ]) {
    const payload = Uint8Array.from({ length }, (_, i) => (i * 73) ^ (i >>> 8));
    const stream = join(hex(header), payload);
    const expected = join(hex(prefix), payload);
    assert.deepEqual(decompressLzmat(stream, expected.length), expected);
    // A fresh tag follows a raw block, regardless of unused old tag bits.
    assert.deepEqual(decompressLzmat(join(stream, hex('005859')), expected.length + 2), join(expected, hex('5859')));
    fails(stream, expected.length - 1, 'output-limit');
    fails(stream.subarray(0, stream.length - 1), expected.length, 'truncated-input');
  }
});

test('truncated distance, length extensions, raw header and raw payload fail with codes', () => {
  for (const stream of [
    '', '418000', '418001', '4180000f',
    '418000ff0f', '418000ff0f00', '418000ffffff', '418000ffffff0f',
  ]) {
    fails(hex(stream), 70000, 'truncated-input');
  }
  // Long-distance modes need their extra byte/nibble even at input end.
  const history = new Uint8Array(0x881).fill(0x41);
  for (const wire of ['02', '0200', '03', '0300']) {
    fails(literalThenMatch(history, wire), 70000, 'truncated-input');
  }
});

test('impossible back references are rejected rather than reading zeroes', () => {
  fails(hex('41800200'), 20, 'invalid-back-reference'); // distance 2, output position 1
  fails(hex('41800100'), 200, 'invalid-back-reference'); // early distance 129
  fails(literalThenMatch(new Uint8Array(0x881), '030000'), 70000, 'invalid-back-reference');
});

test('every prefix of the external fixture either yields its true prefix or a coded truncation', () => {
  for (let length = 0; length <= packedGolden.length; length++) {
    let result;
    try {
      result = decompressLzmat(packedGolden.subarray(0, length), 0x6000);
    } catch (error) {
      assert.ok(error instanceof AnalysisError);
      assert.equal(error.code, 'truncated-input');
      continue;
    }
    assert.deepEqual(result, unpackedGolden.slice(0, result.length), `compressed prefix ${length}`);
  }
});

test('argument validation and every output path enforce the caller ceiling', () => {
  for (const invalid of [undefined, null, [], new ArrayBuffer(4), new Uint16Array(4)]) {
    fails(invalid, 20, 'invalid-input');
  }
  for (const invalid of [undefined, NaN, Infinity, -1, 1.5, '10', 128 * 1024 * 1024 + 1]) {
    fails(hex('41'), invalid, 'invalid-output-limit');
  }
  fails(hex('41'), 0, 'output-limit');
  fails(hex('410042'), 1, 'output-limit');
  fails(hex('41800000'), 3, 'output-limit');
  fails(new Uint8Array(128 * 1024 * 1024 + 1), 20, 'input-too-large');
});

test('typed-array views respect their extent and remain unchanged', () => {
  const storage = hex('deadbeef 41800005 cafebabe');
  const original = storage.slice();
  assert.deepEqual(decompressLzmat(storage.subarray(4, 8), 9), new Uint8Array(9).fill(0x41));
  fails(storage.subarray(4, 7), 9, 'truncated-input');
  assert.deepEqual(storage, original);
});

test('deterministic malformed streams stay bounded and only throw AnalysisError', () => {
  let state = 0x94505857;
  for (let trial = 0; trial < 500; trial++) {
    const input = Uint8Array.from({ length: trial % 67 }, () => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state >>> 24;
    });
    try {
      const output = decompressLzmat(input, 512);
      assert.ok(output.length <= 512);
    } catch (error) {
      assert.ok(error instanceof AnalysisError);
      assert.ok(['truncated-input', 'invalid-back-reference', 'output-limit'].includes(error.code));
    }
  }
});
