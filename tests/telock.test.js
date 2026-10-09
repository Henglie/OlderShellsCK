import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AnalysisError } from '../src/core/errors.js';
import {
  TELOCK_ENGINE,
  TELOCK_ENGINE_BOUNDARY,
  TELOCK_WRAPPER_LAYERS,
  telockToolFileOffset,
  transformTelockDword,
  applyTelockWrapperLayers,
  decompressTelockAplib,
  supportsTelock,
  unpackTelock,
} from '../src/core/unpackers/telock.js';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = bytes => Buffer.from(bytes).toString('hex');
const TOOL = fileURLToPath(new URL('../资料/老旧壳脱壳工具/tElock脱壳机.exe', import.meta.url));
const LAYER2 = fileURLToPath(new URL('../资料/reverse/mt27-research/telock-layer2.bin', import.meta.url));
const AFTER_L3 = fileURLToPath(new URL('../资料/reverse/mt29-telock/telock-after-L3-only.bin', import.meta.url));
const AFTER_L4 = fileURLToPath(new URL('../资料/reverse/mt29-telock/telock-layer3.bin', import.meta.url));
const needs = (...paths) => ({ skip: paths.every(p => existsSync(p)) ? false : 'research artifacts missing' });

test('engine surface stays unsupported and rejects without a target sample', async () => {
  assert.equal(supportsTelock(), false);
  if (existsSync(TOOL)) {
    const tool = new Uint8Array(await readFile(TOOL));
    assert.equal(supportsTelock(tool, {}), false);
    assert.equal(supportsTelock(tool, { machine: 0x14c }), false);
  }
  assert.throws(() => unpackTelock(), error => error instanceof AnalysisError && error.code === 'telock-no-target-sample');
  assert.equal(TELOCK_ENGINE.runtimeVerified, false);
  assert.equal(TELOCK_ENGINE.outputKind, 'none');
  for (const key of ['supports', 'layers', 'codec', 'loader']) assert.ok(TELOCK_ENGINE_BOUNDARY[key]);
});

test('layer table windows, counts and lower-edge chaining are self-consistent', () => {
  assert.equal(TELOCK_WRAPPER_LAYERS.length, 4);
  for (const layer of TELOCK_WRAPPER_LAYERS) {
    assert.equal(layer.window[0], layer.firstVa - 4 * (layer.count - 1));
    assert.equal(layer.window[1], layer.firstVa);
    assert.ok(layer.count > 0);
  }
  for (const i of [0, 1, 2]) {
    assert.equal(TELOCK_WRAPPER_LAYERS[i].window[0], TELOCK_WRAPPER_LAYERS[i + 1].entryVa,
      `layer ${i + 1} lower window edge must chain to layer ${i + 2} entry`);
  }
  assert.equal(TELOCK_WRAPPER_LAYERS[3].nextEntryVa, 0x436451);
  assert.deepEqual(telockToolFileOffset(0x436975), 0x10f75);
  assert.deepEqual(telockToolFileOffset(0x435fff), -1);
});

test('each layer transform is a u32 bijection (known-key roundtrips)', async () => {
  const words = [0x00000000, 0xffffffff, 0x01234567, 0x89abcdef, 0xfd03cb06, 0x6da5154d];
  if (existsSync(TOOL)) {
    const tool = new Uint8Array(await readFile(TOOL));
    for (const layer of TELOCK_WRAPPER_LAYERS) {
      const at = telockToolFileOffset(layer.firstVa);
      words.push(tool[at] | (tool[at + 1] << 8) | (tool[at + 2] << 16) | (tool[at + 3] << 24));
    }
  }
  for (const layer of TELOCK_WRAPPER_LAYERS) {
    const inverse = value => {
      let w = value >>> 0;
      if (layer.postAdd !== undefined) w = (w - layer.postAdd) >>> 0;
      if (layer.postSub !== undefined) w = (w + layer.postSub) >>> 0;
      if (layer.xors) for (const mask of layer.xors) w = (w ^ mask) >>> 0;
      if (layer.preAdd !== undefined) w = (w - layer.preAdd) >>> 0;
      return w >>> 0;
    };
    for (const word of words) assert.equal(inverse(transformTelockDword(layer, word)), word >>> 0, `layer ${layer.index} word ${word.toString(16)}`);
  }
  assert.throws(() => transformTelockDword(TELOCK_WRAPPER_LAYERS[0], -1), error => error instanceof AnalysisError && error.code === 'invalid-input');
  assert.throws(() => transformTelockDword(TELOCK_WRAPPER_LAYERS[0], 0x100000000), error => error instanceof AnalysisError && error.code === 'invalid-input');
});

test('wrapper layer chain replays the tool image into all three golden images', needs(TOOL, LAYER2, AFTER_L3, AFTER_L4), async () => {
  const tool = new Uint8Array(await readFile(TOOL));
  assert.equal(sha(tool), '3c70bf02d83265f6a126f8cfa38a19096421268dbe54e9401f05e93d38e889b2');
  const anchors = { 1: '73eb373a9a860e7489ef3f5f3bdf883020c1a998858671750432ed7224b26bd8',
    2: 'e3df4acb48926083b868d0f0ccff725f8f3f7143e18f705b18258bdf32749901',
    3: 'ef1423e0788618b499ee474259e90ba501faa04dffe77befd78367bc7725a89c',
    4: 'ff7e93f1c572430a9951a61de22ef6a44c71f407d19c7c8aefed861b91409490' };
  const goldens = { 2: new Uint8Array(await readFile(LAYER2)), 3: new Uint8Array(await readFile(AFTER_L3)), 4: new Uint8Array(await readFile(AFTER_L4)) };
  for (const through of [1, 2, 3, 4]) {
    const result = applyTelockWrapperLayers(tool, { through, sha256: sha });
    assert.equal(result.imageSha256, anchors[through], `after L${through}`);
    assert.deepEqual(result.layers.map(l => l.index), Array.from({ length: through }, (_, i) => i + 1));
    if (goldens[through]) assert.deepEqual(result.bytes, goldens[through], `byte equality after L${through}`);
  }
  const zero = applyTelockWrapperLayers(tool, { through: 0 });
  assert.deepEqual(zero.bytes, tool);
  assert.deepEqual(zero.layers, []);
  assert.equal(applyTelockWrapperLayers(tool).imageSha256, undefined);
});

test('wrapper layer application validates inputs and window bounds', () => {
  assert.throws(() => applyTelockWrapperLayers('nope'), error => error instanceof AnalysisError && error.code === 'input-size-limit');
  assert.throws(() => applyTelockWrapperLayers(new Uint8Array([1, 2, 3, 4])), error => error instanceof AnalysisError && error.code === 'telock-window-out-of-range');
  assert.throws(() => applyTelockWrapperLayers(new Uint8Array(0x20000), { through: 5 }), error => error instanceof AnalysisError && error.code === 'invalid-layer');
  const tiny = new Uint8Array(8);
  const layer = { firstVa: 0x1000, count: 2, preAdd: 1 };
  const out = applyTelockWrapperLayers(tiny, { through: 0, offsetOf: () => 0 });
  assert.equal(out.layers.length, 0);
  assert.throws(() => applyTelockWrapperLayers(tiny, { offsetOf: va => va === 0x1000 ? 4 : -1 }),
    error => error instanceof AnalysisError && error.code === 'telock-window-out-of-range');
  assert.ok(layer);
});

class Stream {
  constructor() {
    this.out = []; this.rawQ = []; this.open = false; this.tag = 0; this.n = 0; this.slot = -1;
  }
  putBit(v) {
    if (!this.open) {
      this.out.push(...this.rawQ); this.rawQ = [];
      this.slot = this.out.length; this.out.push(0); this.open = true; this.tag = 0; this.n = 0;
    }
    this.tag = (this.tag << 1) | (v & 1); this.n++;
    if (this.n === 8) { this.out[this.slot] = this.tag & 255; this.open = false; }
  }
  putRaw(b) { this.rawQ.push(b & 255); }
  putBits(v, k) { for (let i = k - 1; i >= 0; i--) this.putBit((v >>> i) & 1); }
  gamma(v) {
    const bin = v.toString(2);
    for (let i = 1; i < bin.length; i++) { this.putBit(+bin[i]); this.putBit(i === bin.length - 1 ? 0 : 1); }
  }
  first(b) { this.out.push(b & 255); }
  lit(b) { this.putBit(0); this.putRaw(b); }
  short(off, len) { this.putBits(0b110, 3); this.putRaw((off << 1) | (len - 2)); }
  nib(n) { this.putBits(0b111, 3); this.putBits(n, 4); }
  long(lead, low, lenGamma) { this.putBits(0b10, 2); this.gamma(lead); this.putRaw(low); this.gamma(lenGamma); }
  rep(lenGamma) { this.putBits(0b10, 2); this.gamma(2); this.gamma(lenGamma); }
  term() { this.putBits(0b110, 3); this.putRaw(0); }
  build() {
    if (this.open) { this.tag <<= 8 - this.n; this.out[this.slot] = this.tag & 255; this.open = false; }
    return Uint8Array.from([...this.out, ...this.rawQ]);
  }
}

test('aPLib-family codec: literal, short-match, nibble and terminator vectors', () => {
  let s = new Stream(); s.first(0x41); s.lit(0x42); s.lit(0x43); s.term();
  let r = decompressTelockAplib(s.build(), 64);
  assert.equal(hex(r.bytes), '414243');
  assert.equal(r.consumed, s.build().length);

  s = new Stream(); s.first(0x41); s.lit(0x42); s.lit(0x43); s.short(2, 3); s.term();
  r = decompressTelockAplib(s.build(), 64);
  assert.equal(hex(r.bytes), '414243424342');

  s = new Stream(); s.first(0x58); s.lit(0x59); s.nib(2); s.nib(0); s.term();
  r = decompressTelockAplib(s.build(), 64);
  assert.equal(hex(r.bytes), '58595800');

  s = new Stream(); s.first(0x61); s.short(1, 3); s.rep(2); s.term();
  r = decompressTelockAplib(s.build(), 64);
  assert.equal(hex(r.bytes), '616161616161');

  s = new Stream(); s.first(0x41); s.lit(0x42); s.nib(15); s.term();
  assert.throws(() => decompressTelockAplib(s.build(), 64), error => error instanceof AnalysisError && error.code === 'invalid-back-reference');
});

test('aPLib-family codec: gamma matches, repeat offsets and the distance length increments', () => {
  let s = new Stream(); s.first(0x11);
  for (let i = 1; i < 0x102; i++) s.lit(0x11);
  s.long(4, 1, 2); s.rep(3); s.term();
  let r = decompressTelockAplib(s.build(), 8192);
  assert.equal(r.bytes.length, 0x102 + 2 + 3);
  assert.ok(r.bytes.every(b => b === 0x11));

  for (const [offset, increment] of [[0x7f, 2], [0x80, 0], [0x500, 1], [0x7cff, 1], [0x7d00, 2]]) {
    s = new Stream(); s.first(0x22);
    for (let i = 1; i < offset + 2; i++) s.lit(0x22);
    s.long((offset >> 8) + 3, offset & 0xff, 2); s.term();
    r = decompressTelockAplib(s.build(), 1 << 20);
    assert.equal(r.bytes.length, offset + 2 + 2 + increment, `offset ${offset.toString(16)}`);
  }
});

test('aPLib-family codec: malformed streams fail closed', () => {
  const failure = (stream, code, maxOutput = 64) =>
    assert.throws(() => decompressTelockAplib(stream, maxOutput), error => error instanceof AnalysisError && error.code === code);
  let s = new Stream(); s.first(0x41); s.rep(3); s.term();
  failure(s.build(), 'invalid-back-reference');
  s = new Stream(); s.first(0x41); s.lit(0x42); s.long(3, 0, 2); s.term();
  failure(s.build(), 'invalid-back-reference');
  s = new Stream(); s.first(0x41); s.long(3, 200, 2); s.term();
  failure(s.build(), 'invalid-back-reference');
  s = new Stream(); s.first(0x41); s.lit(0x42); s.lit(0x43);
  failure(s.build(), 'truncated-input');
  s = new Stream(); s.first(0x41); s.putBits(0b10, 2);
  for (let i = 0; i < 40; i++) { s.putBit(1); s.putBit(1); }
  failure(s.build(), 'telock-integer-overflow');
  s = new Stream(); s.first(0x41); s.lit(0x42); s.term();
  failure(s.build(), 'output-limit', 1);
  assert.throws(() => decompressTelockAplib('nope', 64), error => error instanceof AnalysisError && error.code === 'invalid-input');
  assert.throws(() => decompressTelockAplib(new Uint8Array([0]), -1), error => error instanceof AnalysisError && error.code === 'invalid-output-limit');
});
