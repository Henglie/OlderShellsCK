import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeNrv, decompressNrv } from '../src/core/codecs/nrv.js';
import { AnalysisError } from '../src/core/errors.js';

const variants = ['NRV2B', 'NRV2D', 'NRV2E'];
// Independently hand-calculated prefix codes for 0x1000002, followed by byte ff:
// B: binary prefix tree; D/E: subtract-one, two-bit continuation tree.
const eos = v => ['0' + (v === 'NRV2B' ? '00'.repeat(22) + '1001' : '00010010010010010010010010010010010101'), 255];

// Bit/byte interleaver only: numbers are raw bytes; strings are MSB-first control
// bits stored in LE32 words. It contains no distance/length/compression algorithm.
function stream(events) {
  const bytes = [];
  let at = 0, remaining = 0, word = 0;
  for (const event of events) {
    if (typeof event === 'number') { bytes.push(event); continue; }
    for (const bit of event) {
      if (!remaining) { at = bytes.length; bytes.push(0, 0, 0, 0); remaining = 32; word = 0; }
      remaining--; word = (word | (Number(bit) << remaining)) >>> 0;
      for (let i = 0; i < 4; i++) bytes[at + i] = (word >>> (i * 8)) & 255;
    }
  }
  return Uint8Array.from(bytes);
}
const text = bytes => new TextDecoder().decode(bytes);
const code = expected => e => e instanceof AnalysisError && e.code === expected;

for (const v of variants) {
  test(`${v}: hand-derived literals, EOS, exact subview and consumption`, () => {
    const packed = stream(['1', 65, '1', 66, '1', 67, ...eos(v)]);
    const view = new Uint8Array(packed.length + 11); view.set(packed, 5);
    const r = decodeNrv(view.subarray(5, 5 + packed.length), 3, v);
    assert.equal(text(r.bytes), 'ABC'); assert.equal(r.bytesRead, packed.length);
    assert.equal(text(decompressNrv(packed, 50, v)), 'ABC');
    assert.equal(decodeNrv(stream(eos(v)), 0, v).bytes.length, 0);
    assert.equal(decodeNrv(Uint8Array.from([...packed, 99, 100]), 3, v).bytesRead, packed.length);
  });

  test(`${v}: new distance, reused distance, overlapping forward copy`, () => {
    // Seed AB; prefix 3 selects an explicit two-byte-back reference. Prefix 2 reuses it.
    const tokens = v === 'NRV2B' ? ['011', 1, '01', '001', '11'] :
      v === 'NRV2D' ? ['011', 2, '0', '001', '01'] : ['011', 2, '1', '001', '010'];
    const packed = stream(['1', 65, '1', 66, ...tokens, ...eos(v)]);
    const expected = v === 'NRV2B' ? 'ABABABAB' : v === 'NRV2D' ? 'ABABABA' : 'ABABABABA';
    assert.equal(text(decompressNrv(packed, expected.length, v)), expected);
    assert.throws(() => decompressNrv(packed, expected.length - 1, v), code('output-limit'));
  });

  test(`${v}: long length branch and distance-one overlap`, () => {
    // Prefix 2 reuses initial distance 1. Long count tree '11' yields 3;
    // B/D add 2+1, E adds 3+1, in addition to the seed byte.
    const packed = stream(['1', 65, '001', '00', '11', ...eos(v)]);
    const expected = 'A'.repeat(v === 'NRV2E' ? 8 : 7);
    assert.equal(text(decompressNrv(packed, expected.length, v)), expected);
  });

  test(`${v}: far-distance threshold changes match length`, () => {
    const threshold = v === 'NRV2B' ? 0xd00 : 0x500;
    for (const above of [0, 1]) {
      const distance = threshold + above, events = [];
      for (let i = 0; i < distance; i++) events.push('1', i % 251);
      if (v === 'NRV2B') events.push('0' + (above ? '00000001' : '101011'), above ? 0 : 255, '01');
      else events.push('0' + (above ? '00000011' : '00000001'), above ? 0 : 254, '0');
      const packed = stream([...events, ...eos(v)]);
      const length = (v === 'NRV2D' ? 3 : 2) + above;
      const result = decompressNrv(packed, distance + length, v);
      assert.equal(result.length, distance + length);
      assert.deepEqual([...result.subarray(distance)], Array.from({ length }, (_, i) => i));
    }
  });

  test(`${v}: every truncated prefix, bad references, size and step limits`, () => {
    const packed = stream(['1', 65, '1', 66, ...eos(v)]);
    for (let i = 0; i < packed.length; i++) assert.throws(() => decompressNrv(packed.subarray(0, i), 32, v), AnalysisError);
    assert.throws(() => decompressNrv(stream(['001', '11']), 32, v), code('invalid-back-reference'));
    assert.throws(() => decompressNrv(new Uint8Array(64), 32, v), code('invalid-back-reference'));
    assert.throws(() => decompressNrv(packed, 0, v), code('output-limit'));
    assert.throws(() => decompressNrv(packed, 32, v, { maxSteps: 1 }), code('nrv-step-limit'));
  });
}

test('NRV argument validation precedes allocation', () => {
  for (const value of [null, undefined, [], 'abc']) assert.throws(() => decodeNrv(value, 1, 'NRV2B'), code('invalid-input'));
  for (const limit of [-1, NaN, 0.5, Infinity, 128 * 1024 * 1024 + 1]) {
    assert.throws(() => decodeNrv(new Uint8Array(), limit, 'NRV2B'), code('invalid-output-limit'));
  }
  assert.throws(() => decodeNrv(new Uint8Array(64 * 1024 * 1024 + 1), 0, 'NRV2B'), code('input-size-limit'));
  assert.throws(() => decodeNrv(new Uint8Array(), 0, 'LZMA'), code('unsupported-nrv-variant'));
  for (const opts of [null, { maxSteps: 0 }, { maxSteps: Infinity }, { maxSteps: 1025 }]) {
    assert.throws(() => decodeNrv(new Uint8Array(), 0, 'NRV2B', opts), code('invalid-step-limit'));
  }
});

test('NRV deterministic malformed corpus remains bounded with typed failures', () => {
  let seed = 0x9e3779b9;
  for (let i = 0; i < 600; i++) {
    const input = new Uint8Array(i % 91);
    for (let j = 0; j < input.length; j++) { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; input[j] = seed >>> 24; }
    for (const v of variants) {
      try { assert.ok(decodeNrv(input, 512, v).bytes.length <= 512); }
      catch (e) { assert.ok(e instanceof AnalysisError, e.stack); }
    }
  }
});
