import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { decodeLzma1 } from '../src/core/compression/lzma.js';
const hex = value => new Uint8Array(Buffer.from(value, 'hex'));
const vector = hex('00241949986f100f063ea50c34f8de11874e0bfffff7a74000');
const expected = new TextEncoder().encode('Hello LZMA! '.repeat(8));

test('raw LZMA1 decodes independent liblzma lc4 vector including EOS', () => {
  const result = decodeLzma1(vector, expected.length, { props: 0x5e, dictionarySize: 4096 });
  assert.deepEqual(result.bytes, expected);
  assert.equal(result.endMarker, true);
  assert.equal(result.consumed, vector.length);
});
test('raw LZMA1 honors typed-array offsets and leaves source unchanged', () => {
  const container = new Uint8Array(vector.length + 12).fill(0xcc); container.set(vector, 7);
  const before = container.slice();
  assert.deepEqual(decodeLzma1(container.subarray(7, 7 + vector.length), 96, { props: 0x5e, dictionarySize: 4096 }).bytes, expected);
  assert.deepEqual(container, before);
});
test('every truncated prefix of independent LZMA1 vector is refused', () => {
  for (let n = 0; n < vector.length; n++) assert.throws(() => decodeLzma1(vector.subarray(0, n), 96, { props: 0x5e, dictionarySize: 4096 }), undefined, `prefix ${n}`);
});
test('wrong output length is not silently truncated or padded', () => {
  for (const size of [1, 20, 95, 97, 128]) assert.throws(() => decodeLzma1(vector, size, { props: 0x5e, dictionarySize: 4096 }));
});
test('LZMA properties, dictionary and range initializer are bounded', () => {
  for (const props of [-1, 225, 255, 8]) assert.throws(() => decodeLzma1(vector, 96, { props, dictionarySize: 4096 }));
  for (const dictionarySize of [0, 4095, 0x80000001, Infinity]) assert.throws(() => decodeLzma1(vector, 96, { dictionarySize }));
  for (const size of [-1, 1.5, 128 * 1024 * 1024 + 1]) assert.throws(() => decodeLzma1(vector, size));
  const bad = vector.slice(); bad[0] = 1; assert.throws(() => decodeLzma1(bad, 96));
  assert.throws(() => decodeLzma1(hex('00ffffffff'), 96));
});
test('LZMA literals, matched literals, repeat distances and long distances agree with independent compressor', t => {
  const expected = Uint8Array.from({ length: 100000 }, (_, i) => i < 65000 ? (i * 17 + (i >>> 8) * 31) & 255 : ((i - 64000) * 17 + ((i - 64000) >>> 8) * 31) & 255);
  let vectors;
  try {
    vectors = JSON.parse(execFileSync('py', ['-3.11', '-B', '-c',
      "import lzma,json; d=bytes((i*17+(i>>8)*31)&255 if i<65000 else ((i-64000)*17+((i-64000)>>8)*31)&255 for i in range(100000)); print(json.dumps([lzma.compress(d,format=lzma.FORMAT_RAW,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':131072,'lc':lc,'lp':lp,'pb':pb}]).hex() for lc,lp,pb in [(3,0,2),(4,0,2),(2,2,1)]]))"], { encoding: 'utf8', timeout: 15000 }));
  } catch (error) { t.skip(`independent Python/liblzma oracle unavailable: ${error.code}`); return; }
  for (const [i, props] of [0x5d, 0x5e, 0x41].entries()) {
    const result = decodeLzma1(hex(vectors[i]), expected.length, { props, dictionarySize: 131072 });
    assert.deepEqual(result.bytes, expected); assert.equal(result.endMarker, true);
  }
});
