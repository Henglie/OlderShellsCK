import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AnalysisError } from '../src/core/errors.js';
import { parsePE } from '../src/core/pe.js';
import {
  NSPACK_ENGINE,
  NSPACK_ENGINE_BOUNDARY,
  supportsNsPack,
  decodeNsPackBlob,
  restoreNsPackRedirects,
  parseNsPackImportWalk,
  unpackNsPack,
} from '../src/core/unpackers/nspack.js';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = bytes => Buffer.from(bytes).toString('hex');
const SAMPLE = fileURLToPath(new URL('../资料/老旧壳脱壳工具/UnObSiDium/UnObSiDium.exe', import.meta.url));
const BLOB_WRAPPER = fileURLToPath(new URL('../资料/reverse/t42-nspack/blob-wrapper/input.exe', import.meta.url));
const needs = (...paths) => ({ skip: paths.every(p => existsSync(p)) ? false : 'research artifacts missing' });
const SAMPLE_SHA = '5292383439ca10f357c2fa3cc64047bbe1fcffe3ccb70ce2dfd5e66469612cda';

test('engine surface stays honest and rejects non-matching inputs', async () => {
  assert.equal(NSPACK_ENGINE.id, 'nspack-pe32');
  assert.equal(NSPACK_ENGINE.family, 'NsPack');
  assert.equal(NSPACK_ENGINE.catalogId, 'nspack');
  assert.equal(NSPACK_ENGINE.outputKind, 'analysis-pe');
  assert.equal(NSPACK_ENGINE.runtimeVerified, false);
  for (const key of ['sample', 'stage1', 'stage2', 'redirects', 'imports', 'notRestored']) {
    assert.ok(NSPACK_ENGINE_BOUNDARY[key], `boundary key ${key}`);
  }
  assert.equal(supportsNsPack(), false);
  assert.equal(supportsNsPack(new Uint8Array([0x4d, 0x5a]), null), false);
  assert.equal(supportsNsPack('nope', {}), false);
  assert.throws(() => unpackNsPack(new Uint8Array(16)), error => error instanceof AnalysisError && error.code === 'not-pe');
  if (existsSync(SAMPLE)) {
    const bytes = new Uint8Array(await readFile(SAMPLE));
    const pe = parsePE(bytes);
    assert.equal(sha(bytes), SAMPLE_SHA);
    assert.equal(supportsNsPack(bytes, pe), true);
    const broken = bytes.slice();
    broken[pe.entryPointOffset] = 0x90;
    assert.equal(supportsNsPack(broken, parsePE(broken)), false);
    assert.throws(() => unpackNsPack(broken), error => error instanceof AnalysisError && error.code === 'unsupported-variant');
  }
});

test('stage-1 codec blob: golden replay against the Ghidra-staged artifact', needs(SAMPLE, BLOB_WRAPPER), async () => {
  const bytes = new Uint8Array(await readFile(SAMPLE));
  const pe = parsePE(bytes);
  // The stub computes the blob source as (entry+0x62) + 0x367 = entry+0x3c9 (VA 0x4fb9c1).
  const at = pe.entryPointOffset + 0x3c9;
  const decoded = decodeNsPackBlob(bytes.subarray(at, at + 0x53d), 1 << 16);
  assert.equal(decoded.consumed, 0x53d);
  assert.equal(decoded.bytes.length, 1681);
  assert.equal(sha(decoded.bytes), 'b1b221f80fe379b3a5d7e5fc1b8c1ea0d06afcf99d5de8f10b43a55f259417f8');
  const wrapper = new Uint8Array(await readFile(BLOB_WRAPPER));
  assert.deepEqual(decoded.bytes, wrapper.subarray(0x400, 0x400 + 1681));
});

// Bitstream model per stub VA 0x4fb919 (ADD DL,DL): each tag byte contributes
// its 8 bits MSB-first; the refill-time carry bit rides between groups and is
// never a data bit. A tag byte is allocated at the position where the decoder
// refills it, so raw bytes emitted between two of its bits still land after it.
class NsStream {
  constructor() { this.src = []; this.tagAt = -1; this.tagUsed = 8; }
  bit(v) {
    if (this.tagUsed === 8) { this.tagAt = this.src.length; this.src.push(0); this.tagUsed = 0; }
    this.src[this.tagAt] |= (v & 1) << (7 - this.tagUsed);
    this.tagUsed++;
  }
  raw(b) { this.src.push(b & 0xff); }
  gamma(v) {
    const bin = v.toString(2);
    for (let i = 1; i < bin.length; i++) { this.bit(+bin[i]); this.bit(i === bin.length - 1 ? 0 : 1); }
  }
  first(b) { this.src.push(b & 0xff); }
  lit(b) { this.bit(0); this.raw(b); }
  short(off, len) { this.bit(1); this.bit(1); this.bit(0); this.raw((off << 1) | (len - 2)); }
  nib(n) { this.bit(1); this.bit(1); this.bit(1); this.bit((n >> 3) & 1); this.bit((n >> 2) & 1); this.bit((n >> 1) & 1); this.bit(n & 1); }
  long(lead, low, lenGamma) { this.bit(1); this.bit(0); this.gamma(lead); this.raw(low); this.gamma(lenGamma); }
  rep(lenGamma) { this.bit(1); this.bit(0); this.gamma(2); this.gamma(lenGamma); }
  term() { this.bit(1); this.bit(1); this.bit(0); this.raw(0); }
  build() { return Uint8Array.from(this.src); }
}

test('codec: literal, short-match, nibble and terminator vectors', () => {
  let s = new NsStream(); s.first(0x41); s.lit(0x42); s.lit(0x43); s.term();
  let stream = s.build();
  let r = decodeNsPackBlob(stream, 64);
  assert.equal(hex(r.bytes), '414243');
  assert.equal(r.consumed, stream.length);

  s = new NsStream(); s.first(0x41); s.lit(0x42); s.lit(0x43); s.short(2, 3); s.term();
  r = decodeNsPackBlob(s.build(), 64);
  assert.equal(hex(r.bytes), '414243424342');

  s = new NsStream(); s.first(0x58); s.lit(0x59); s.nib(2); s.nib(0); s.term();
  r = decodeNsPackBlob(s.build(), 64);
  assert.equal(hex(r.bytes), '58595800');

  s = new NsStream(); s.first(0x61); s.short(1, 3); s.rep(2); s.term();
  r = decodeNsPackBlob(s.build(), 64);
  assert.equal(hex(r.bytes), '616161616161');

  s = new NsStream(); s.first(0x41); s.lit(0x42); s.nib(15); s.term();
  assert.throws(() => decodeNsPackBlob(s.build(), 64), error => error instanceof AnalysisError && error.code === 'invalid-back-reference');
});

test('codec: gamma matches, repeat offsets and the distance length increments', () => {
  let s = new NsStream(); s.first(0x11);
  for (let i = 1; i < 0x102; i++) s.lit(0x11);
  s.long(4, 1, 2); s.rep(3); s.term();
  let r = decodeNsPackBlob(s.build(), 8192);
  assert.equal(r.bytes.length, 0x102 + 2 + 3);
  assert.ok(r.bytes.every(b => b === 0x11));

  for (const [offset, increment] of [[0x7f, 2], [0x80, 0], [0x500, 1], [0x7cff, 1], [0x7d00, 2]]) {
    s = new NsStream(); s.first(0x22);
    for (let i = 1; i < offset + 2; i++) s.lit(0x22);
    s.long((offset >> 8) + 3, offset & 0xff, 2); s.term();
    r = decodeNsPackBlob(s.build(), 1 << 20);
    assert.equal(r.bytes.length, offset + 2 + 2 + increment, `offset ${offset.toString(16)}`);
  }
});

test('codec: malformed streams fail closed with stable codes', () => {
  const failure = (stream, code, maxOutput = 64) =>
    assert.throws(() => decodeNsPackBlob(stream, maxOutput), error => error instanceof AnalysisError && error.code === code);
  let s = new NsStream(); s.first(0x41); s.rep(3); s.term();
  failure(s.build(), 'invalid-back-reference');
  s = new NsStream(); s.first(0x41); s.lit(0x42); s.long(3, 0, 2); s.term();
  failure(s.build(), 'invalid-back-reference');
  s = new NsStream(); s.first(0x41); s.long(3, 200, 2); s.term();
  failure(s.build(), 'invalid-back-reference');
  s = new NsStream(); s.first(0x41); s.lit(0x42); s.lit(0x43);
  failure(s.build(), 'truncated-input');
  s = new NsStream(); s.first(0x41); s.bit(1); s.bit(0);
  for (let i = 0; i < 40; i++) { s.bit(1); s.bit(1); }
  failure(s.build(), 'nspack-integer-overflow');
  s = new NsStream(); s.first(0x41); s.lit(0x42); s.term();
  failure(s.build(), 'output-limit', 1);
  assert.throws(() => decodeNsPackBlob('nope', 64), error => error instanceof AnalysisError && error.code === 'invalid-input');
  assert.throws(() => decodeNsPackBlob(new Uint8Array([0]), -1), error => error instanceof AnalysisError && error.code === 'invalid-output-limit');
});

test('redirect restorer: mode-1 tag filter, data-anchored value and chained e8/e9', () => {
  // One e8 at body offset 0x10 with packed rel 0x0E110005 (low byte == tag 5).
  const body = new Uint8Array(0x40);
  body.set([0xe8, 0x05, 0x00, 0x11, 0x0e], 0x10);
  const bodyRva = 0x1000;
  let out = restoreNsPackRedirects(body, bodyRva, { count: 1, tag: 5, mode: 1 });
  assert.deepEqual(out.patched, [{ at: 0x11, rva: 0x1011 }]);
  const newRel = (body[0x11] | (body[0x12] << 8) | (body[0x13] << 16) | (body[0x14] << 24)) >>> 0;
  assert.equal(newRel, (0x110e - 0x1011 + bodyRva) >>> 0);

  // Tag miss is skipped; a later e9 with the tag byte is the one patched.
  const mixed = new Uint8Array(0x40);
  mixed.set([0xe8, 0x07, 0x00, 0x11, 0x0e], 0x10);
  mixed.set([0xe9, 0x05, 0x00, 0x22, 0x0e], 0x20);
  out = restoreNsPackRedirects(mixed, bodyRva, { count: 1, tag: 5, mode: 1 });
  assert.deepEqual(out.patched, [{ at: 0x21, rva: 0x1021 }]);

  // Chained: the byte right after a patched rel32 is e9 -> patched from the same budget.
  const chained = new Uint8Array(0x40);
  chained.set([0xe8, 0x05, 0x00, 0x11, 0x0e], 0x10);
  chained.set([0xe9, 0x05, 0x00, 0x22, 0x0e], 0x15);
  out = restoreNsPackRedirects(chained, bodyRva, { count: 2, tag: 5, mode: 1 });
  assert.equal(out.patched.length, 2);
  assert.deepEqual(out.patched.map(p => p.at), [0x11, 0x16]);

  // Mode 0: instruction-verified bswap32, no tag filter.
  const plain = new Uint8Array(0x40);
  plain.set([0xe8, 0xdd, 0xcc, 0xbb, 0xaa], 0x10);
  out = restoreNsPackRedirects(plain, bodyRva, { count: 1, tag: 0, mode: 0 });
  assert.deepEqual(out.patched, [{ at: 0x11, rva: 0x1011 }]);
  const swapped = (plain[0x11] | (plain[0x12] << 8) | (plain[0x13] << 16) | (plain[0x14] << 24)) >>> 0;
  assert.equal(swapped, (0xDDCCBBAA - 0x1011 + bodyRva) >>> 0);

  assert.throws(() => restoreNsPackRedirects('nope', 0x1000, { count: 1, tag: 0, mode: 0 }), error => error instanceof AnalysisError && error.code === 'invalid-input');
  assert.throws(() => restoreNsPackRedirects(new Uint8Array(16), 0x1000, { count: 0, tag: 0, mode: 0 }), error => error instanceof AnalysisError && error.code === 'invalid-nspack-redirect-count');
  assert.throws(() => restoreNsPackRedirects(new Uint8Array(16), 0x1000, { count: 1, tag: 0, mode: 2 }), error => error instanceof AnalysisError && error.code === 'invalid-input');
});

test('import walk: records, ordinals, terminator and bounds', () => {
  const body = new Uint8Array(0x300);
  const enc = new TextEncoder();
  const put32 = (at, v) => { body[at] = v & 0xff; body[at + 1] = (v >>> 8) & 0xff; body[at + 2] = (v >>> 16) & 0xff; body[at + 3] = (v >>> 24) & 0xff; };
  body.set(enc.encode('KERNEL32.DLL\0'), 0x200);
  body.set(enc.encode('CreateFileW'), 0x210);   // 11 bytes -> next name at 0x21b
  body.set(enc.encode('ReadFile'), 0x21b);      // 8 bytes -> next name at 0x223
  body.set([0xff, 0x28, 0x00, 0x00, 0x00], 0x223); // ordinal entry (marker + dword)
  // record at 0x110: size=0x11+3, dllOff, iatRva, nameAreaOff(->0x210), lengths 11,8,5,0
  put32(0x110, 0x14); put32(0x114, 0); put32(0x118, 0x5000); put32(0x11c, 0x100);
  body[0x120] = 11; body[0x121] = 8; body[0x122] = 5; body[0x123] = 0;
  // terminator (12 zero bytes) at 0x124
  const walk = parseNsPackImportWalk(body, 0x1000, 0x1000 + 0x110, 0x1000 + 0x200);
  assert.equal(walk.endOffset, 0x124);
  assert.deepEqual(walk.modules, [{
    dll: 'KERNEL32.DLL', iatRva: 0x5000,
    functions: [{ name: 'CreateFileW', length: 11 }, { name: 'ReadFile', length: 8 }, { ordinal: 0x28, length: 5 }],
  }]);

  const failure = (fn, code) => assert.throws(fn, error => error instanceof AnalysisError && error.code === code);
  failure(() => parseNsPackImportWalk(body, 0x1000, 0x1000 + 0x110, 0x2000), 'invalid-nspack-import-walk');
  failure(() => parseNsPackImportWalk(body, 0x1000, 0x2000, 0x1000 + 0x200), 'invalid-nspack-import-walk');
  const badSize = body.slice();
  badSize[0x110] = 0x15; // size inconsistent with 3 function entries (0x11 + 3 = 0x14)
  failure(() => parseNsPackImportWalk(badSize, 0x1000, 0x1000 + 0x110, 0x1000 + 0x200), 'invalid-nspack-import-walk');
});

test('end-to-end: UnObSiDium.exe (NsPack 3.7) unpacks to a pinned analysis PE', needs(SAMPLE), async () => {
  const bytes = new Uint8Array(await readFile(SAMPLE));
  assert.equal(sha(bytes), SAMPLE_SHA);
  const result = unpackNsPack(bytes);
  assert.equal(sha(result.bytes), '5bd7156d47d8b60217288a98e89864a269ae09f433b20eda4c1e452ea60e7b55');
  assert.equal(result.metadata.engine, 'nspack-pe32');
  assert.equal(result.metadata.outputKind, 'analysis-pe');
  assert.equal(result.metadata.runtimeVerified, false);
  assert.equal(result.metadata.originalEntryPoint, 0x295c);
  assert.equal(result.metadata.importedModules, 10);
  assert.equal(result.metadata.importedFunctions, 124);
  assert.equal(result.metadata.restoredRedirects, 1066);
  assert.equal(result.metadata.lzmaProperties, 'lc=3 lp=0 pb=2');
  assert.equal(result.metadata.decompressedSize, 1024000);
  assert.ok(result.metadata.warnings.includes('runtime-not-verified'));
  assert.ok(result.metadata.warnings.includes('e8e9-call-redirect-restored'));

  const pe = parsePE(result.bytes);
  assert.deepEqual(pe.sections.map(s => s.name), ['.nspbody', '.rsrc', '.idata']);
  assert.deepEqual(pe.imports.map(m => `${m.name}:${m.functions.length}`).sort(), [
    'COMCTL32.DLL:1', 'COMDLG32.DLL:1', 'GDI32.DLL:6', 'GDI32.DLL:7', 'KERNEL32.DLL:27',
    'KERNEL32.DLL:42', 'SHELL32.DLL:3', 'USER32.DLL:24', 'USER32.DLL:4', 'WINMM.DLL:9',
  ]);
  assert.equal(pe.imports.reduce((n, m) => n + m.functions.length, 0), 124);
});
