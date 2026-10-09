import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Script } from 'node:vm';
import { Bytes, matchHex, entropy, MAX_INPUT, MAX_OUTPUT } from '../src/core/bytes.js';
import { AnalysisError } from '../src/core/errors.js';
import { parsePE } from '../src/core/pe.js';
import { detect, DIE_SCOPE } from '../src/core/detect.js';
import { analyze, capabilities, execute, unpack } from '../src/core/index.js';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const coded = code => error => error instanceof AnalysisError && (!code || error.code === code);
const hex = text => Uint8Array.from(Buffer.from(text, 'hex'));
const materialize = (pattern, wildcard = 'a5') => hex(pattern.replaceAll('..', wildcard));
const view = bytes => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const put16 = (bytes, offset, value) => view(bytes).setUint16(offset, value, true);
const put32 = (bytes, offset, value) => view(bytes).setUint32(offset, value, true);
const text = (bytes, offset, value) => bytes.set(Buffer.from(value, 'ascii'), offset);

// Authored here: inert PE headers and a return-zero instruction sequence.
// Nothing in these tests loads or executes a PE. No external fixture required.
function minimalPE({ is64 = false, rawSize = 0x200, overlay = 0 } = {}) {
  const bytes = new Uint8Array(0x200 + rawSize + overlay);
  const optional = 0x98, section = optional + (is64 ? 0xf0 : 0xe0);
  put16(bytes, 0, 0x5a4d); put32(bytes, 0x3c, 0x80); put32(bytes, 0x80, 0x4550);
  put16(bytes, 0x84, is64 ? 0x8664 : 0x14c); put16(bytes, 0x86, 1);
  put16(bytes, 0x94, is64 ? 0xf0 : 0xe0); put16(bytes, 0x96, 0x102);
  put16(bytes, optional, is64 ? 0x20b : 0x10b);
  put32(bytes, optional + 16, 0x1000); put32(bytes, optional + 20, 0x1000);
  if (is64) view(bytes).setBigUint64(optional + 24, 0x140000000n, true);
  else put32(bytes, optional + 28, 0x400000);
  put32(bytes, optional + 32, 0x1000); put32(bytes, optional + 36, 0x200);
  put32(bytes, optional + 56, Math.ceil((0x1000 + rawSize) / 0x1000) * 0x1000);
  put32(bytes, optional + 60, 0x200); put16(bytes, optional + 68, 3);
  put32(bytes, optional + (is64 ? 108 : 92), 16);
  text(bytes, section, '.text'); put32(bytes, section + 8, rawSize);
  put32(bytes, section + 12, 0x1000); put32(bytes, section + 16, rawSize);
  put32(bytes, section + 20, 0x200); put32(bytes, section + 36, 0x60000020);
  bytes.set(hex('31c0c3'), 0x200);
  return bytes;
}

function withImports(is64 = false, rawSize = 0x200, overlay = 0) {
  const bytes = minimalPE({ is64, rawSize, overlay });
  const directory = 0x98 + (is64 ? 112 : 96);
  put32(bytes, directory + 8, 0x1040); put32(bytes, directory + 12, 40);
  // OriginalFirstThunk=0 deliberately exercises FirstThunk fallback.
  put32(bytes, 0x24c, 0x1090); put32(bytes, 0x250, 0x10c0);
  text(bytes, 0x290, 'KERNEL32.dll\0');
  put32(bytes, 0x2c0, 0x10a0); put16(bytes, 0x2a0, 7);
  text(bytes, 0x2a2, 'ExitProcess\0');
  put32(bytes, is64 ? 0x2c8 : 0x2c4, is64 ? 123 : 0x8000007b);
  if (is64) put32(bytes, 0x2cc, 0x80000000);
  return bytes;
}

test('byte reads, strings and patterns honor the exact typed-array extent', () => {
  const storage = hex('dead010203040500beef'), original = storage.slice();
  const bytes = storage.subarray(2, 8), reader = new Bytes(bytes);
  assert.equal(reader.u32(0), 0x04030201);
  assert.equal(reader.cstring(4, 2), '\x05');
  for (const [offset, length] of [[-1, 1], [0.5, 1], [0, NaN], [6, 1], [1, 6], [Infinity, 0], [Number.MAX_SAFE_INTEGER, 2]]) {
    assert.throws(() => reader.range(offset, length), coded('truncated-input'));
  }
  assert.doesNotThrow(() => reader.range(6, 0));
  assert.throws(() => reader.u32(3), coded('truncated-input'));
  assert.throws(() => reader.cstring(0, 5), coded('unterminated-string'));
  assert.ok(matchHex(bytes, 0, '01..0304'));
  for (const [offset, pattern] of [[null, '01'], [-1, '01'], [0.5, '01'], [5, '00..'], [0, '0'], [0, '??'], [0, ''], [0, '02']]) {
    assert.equal(matchHex(bytes, offset, pattern), false);
  }
  assert.deepEqual(storage, original);
  assert.equal(entropy(new Uint8Array()), 0);
  assert.equal(entropy(Uint8Array.from({ length: 256 }, (_, i) => i)), 8);
});

test('authored PE32 and PE32+ parse headers, imports, views, overlay and zero-fill boundaries', () => {
  for (const is64 of [false, true]) {
    const bytes = withImports(is64, 0x200, 16), original = bytes.slice();
    const storage = new Uint8Array(bytes.length + 19); storage.set(bytes, 7);
    const pe = parsePE(storage.subarray(7, 7 + bytes.length));
    assert.equal(pe.format, is64 ? 'PE32+' : 'PE32');
    assert.equal(pe.architecture, is64 ? 'x64' : 'x86');
    assert.equal(pe.imageBase, is64 ? '0x140000000' : '0x400000');
    assert.equal(pe.entryPointRva, 0x1000); assert.equal(pe.entryPointOffset, 0x200);
    assert.deepEqual(pe.imports, [{ name: 'KERNEL32.dll', firstThunk: 0x10c0, functions: [{ name: 'ExitProcess', hint: 7 }, { ordinal: 123 }] }]);
    assert.deepEqual(pe.overlay, { offset: 0x400, size: 16 });
    assert.deepEqual(pe.warnings, []);
    assert.equal(pe.rvaToOffset(0x1ff), 0x1ff);
    assert.equal(pe.rvaToOffset(0x1ff, 2), null);
    assert.equal(pe.rvaToOffset(0x11ff), 0x3ff);
    for (const [rva, size] of [[0x1200, 1], [0x11ff, 2], [-1, 1], [0x1000, -1], [NaN, 1], [0x1000, 0.5]]) assert.equal(pe.rvaToOffset(rva, size), null);
    put32(bytes, pe.sectionTable + 8, 0x1000);
    assert.equal(parsePE(bytes).rvaToOffset(0x1200), null, 'virtual zero-fill is not file data');
    assert.deepEqual(storage.subarray(7, 7 + original.length), original);
  }
});

test('malformed PE headers and offsets fail with bounded domain errors', () => {
  const cases = [
    ['DOS magic', 0, 0, 2, 'not-pe'], ['e_lfanew below DOS', 0x3c, 0x3f, 4, 'invalid-pe-header'],
    ['e_lfanew overflow', 0x3c, 0xffffffff, 4, 'truncated-input'], ['PE signature', 0x80, 0, 4, 'not-pe'],
    ['no sections', 0x86, 0, 2, 'invalid-section-count'], ['too many sections', 0x86, 97, 2, 'invalid-section-count'],
    ['optional magic', 0x98, 0, 2, 'unsupported-pe-magic'], ['short optional', 0x94, 95, 2, 'invalid-optional-header'],
    ['too many directories', 0xf4, 17, 4, 'invalid-directories'], ['directory over optional', 0x94, 0x60, 2, 'invalid-directories'],
    ['headers too small', 0xd4, 0x180, 4, 'invalid-header-size'], ['headers past EOF', 0xd4, 0x401, 4, 'invalid-header-size'],
    ['raw overlap headers', 0x18c, 0x100, 4, 'section-overlaps-headers'], ['raw past EOF', 0x188, 0x201, 4, 'truncated-input'],
    ['RVA wraps uint32', 0x184, 0xffffff00, 4, 'invalid-section-rva'],
  ];
  for (const [label, offset, value, width, code] of cases) {
    const bytes = minimalPE();
    (width === 2 ? put16 : put32)(bytes, offset, value);
    assert.throws(() => parsePE(bytes), coded(code), label);
  }
  assert.throws(() => parsePE(new Uint8Array(MAX_INPUT + 1)), coded('input-size-limit'));
  const bytes = minimalPE();
  for (let length = 0; length < bytes.length; length++) {
    assert.throws(() => parsePE(bytes.subarray(0, length)), coded(), `prefix ${length}`);
  }
});

test('invalid core inputs produce AnalysisError, never native TypeError', () => {
  for (const bytes of [null, undefined, [], new ArrayBuffer(64), new Uint16Array(64), { length: 64 }]) {
    assert.throws(() => parsePE(bytes), coded(), String(bytes));
  }
});

test('import tables are bounded by descriptor size and the 4096-thunk ceiling', () => {
  const missingTerminator = withImports();
  put32(missingTerminator, 0x104, 20);
  assert.ok(parsePE(missingTerminator).warnings.includes('import-limit'));
  const badName = withImports(); put32(badName, 0x24c, 0xffffffff);
  assert.ok(parsePE(badName).warnings.includes('invalid-import-name'));
  const thunks = withImports(false, 0x5000);
  for (let i = 0; i < 4096; i++) put32(thunks, 0x2c0 + i * 4, 0x80000001);
  assert.ok(parsePE(thunks).warnings.includes('import-limit'));
  const highThunk = withImports(true); put32(highThunk, 0x2c4, 1);
  assert.ok(parsePE(highThunk).warnings.includes('invalid-import-thunk'));
  const descriptors = withImports(false, 0x1800);
  put32(descriptors, 0x100, 0x1200); put32(descriptors, 0x104, 257 * 20);
  for (let i = 0; i < 256; i++) descriptors.set(descriptors.subarray(0x240, 0x254), 0x400 + i * 20);
  assert.ok(parsePE(descriptors).warnings.includes('import-limit'), 'terminator beyond descriptor budget is not read');
});

test('overlapping sections are diagnosed and ambiguous RVAs cannot map', () => {
  const bytes = minimalPE();
  put16(bytes, 0x86, 2); bytes.copyWithin(0x1a0, 0x178, 0x1a0);
  const pe = parsePE(bytes);
  assert.ok(pe.warnings.includes('overlapping-raw-sections'));
  assert.ok(pe.warnings.includes('overlapping-virtual-sections'));
  assert.equal(pe.rvaToOffset(0x1000), null);
  assert.equal(pe.entryPointOffset, null);
});

test('REGRESSION: a section overlapping header RVAs must not yield a silently chosen mapping', () => {
  const bytes = minimalPE(); put32(bytes, 0x184, 0x100); put32(bytes, 0xa8, 0x100);
  let pe;
  try { pe = parsePE(bytes); } catch (error) { assert.ok(coded()(error)); return; }
  assert.equal(pe.rvaToOffset(0x100), null, 'header RVA and section RVA refer to different file bytes');
  assert.ok(pe.warnings.length > 0);
});

test('REGRESSION: import strings cannot read unmapped overlay as RVA-backed bytes', () => {
  for (const kind of ['module', 'function']) {
    const bytes = withImports(false, 0x200, 16);
    if (kind === 'module') { put32(bytes, 0x24c, 0x11fc); text(bytes, 0x3fc, 'EVIL'); }
    else { put32(bytes, 0x2c0, 0x11fa); text(bytes, 0x3fc, 'EVIL'); }
    text(bytes, 0x400, 'GHOST.dll\0');
    const pe = parsePE(bytes);
    assert.ok(pe.warnings.length > 0 || !JSON.stringify(pe.imports).includes('GHOST'), `${kind}: bytes at file 0x400 have no RVA`);
  }
});

const vendor = new URL('../vendor/die/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', vendor), 'utf8'));
const fsgSource = await readFile(new URL('db/PE/packer_FSG.2.sg', vendor), 'utf8');
const fsgDataset = JSON.parse(await readFile(new URL('fsg-patterns.json', vendor), 'utf8'));
// Execute only pinned MIT JavaScript rule text with a stub PE API; never PE bytes.
// This independently observes branch metadata instead of copying vendor-die.mjs's regex.
const fsgScript = new Script(`${fsgSource}\ndetect();`);
function upstreamFsg(compareEP) {
  const context = { PE: { compareEP }, meta() {}, result() {}, sVersion: '', sOptions: '', bDetected: false };
  fsgScript.runInNewContext(context, { timeout: 100 });
  return { version: context.sVersion, options: context.sOptions };
}

test('DIE source hashes, MIT notices and all 44 generated FSG records match the pinned source', async t => {
  assert.equal(manifest.commit, '11cb5cb00f8763426005914ed3d983e729760749');
  assert.equal(manifest.license, 'MIT');
  assert.equal(digest(Buffer.from(fsgSource)), '0a911be7bb4ec6a83353ef15bb20be3db4487d70552c756a9d8f2ed9bba93fcd');
  for (const entry of manifest.files) assert.equal(digest(await readFile(new URL(entry.path, vendor))), entry.sha256, entry.path);
  assert.match(await readFile(new URL('LICENSE', vendor), 'utf8'), /Copyright \(c\) 2012-2026 hors/);
  assert.match(await readFile(new URL('../licenses/retdec-MIT.txt', import.meta.url), 'utf8'), /Copyright \(c\) 2017 Avast Software/);
  const patterns = [];
  upstreamFsg(pattern => { patterns.push(pattern); return false; });
  assert.equal(patterns.length, 44);
  const expected = patterns.map(pattern => ({ pattern, ...upstreamFsg(candidate => candidate === pattern) }));
  assert.deepEqual(fsgDataset, expected);
  for (const path of ['bytes.js', 'pe.js', 'detect.js', 'index.js', 'unpackers/mpress.js']) {
    t.diagnostic(`Audit SHA-256 src/core/${path}: ${digest(await readFile(new URL(`../src/core/${path}`, import.meta.url)))}`);
  }
});

test('all 44 FSG signatures handle wildcards, versions, options, position and architecture', () => {
  for (const rule of fsgDataset) {
    for (const wildcard of ['00', 'a5', 'ff']) {
      const bytes = minimalPE(); bytes.set(materialize(rule.pattern, wildcard), 0x200);
      const actual = detect(bytes, parsePE(bytes)).find(hit => hit.family === 'FSG');
      const epHex = Buffer.from(bytes.subarray(0x200)).toString('hex');
      const expected = upstreamFsg(pattern => new RegExp(`^${pattern}`, 'i').test(epHex));
      assert.ok(actual, rule.pattern); assert.equal(actual.version, expected.version);
      assert.equal(actual.evidence[0].options, expected.options);
      assert.equal(actual.source, 'die-rule-subset'); assert.equal(actual.confidence, 'signature');
      const first = bytes[0x200]; bytes[0x200] ^= 0xff;
      assert.equal(detect(bytes, parsePE(bytes)).some(hit => hit.family === 'FSG'), false, 'fixed opcode mutation');
      bytes[0x200] = first;
      put32(bytes, 0xa8, 0x1100);
      assert.equal(detect(bytes, parsePE(bytes)).some(hit => hit.family === 'FSG'), false);
      put32(bytes, 0xa8, 0x1000); put16(bytes, 0x84, 0x1c4);
      assert.equal(detect(bytes, parsePE(bytes)).some(hit => hit.family === 'FSG'), false);
    }
  }
});

test('UPX entry-point branches and low-confidence section clues keep their stated scope', () => {
  for (const is64 of [false, true]) for (const shifted of [false, true]) {
    const bytes = minimalPE({ is64 });
    const shift = shifted ? (is64 ? 24 : 27) : 0;
    if (shifted) bytes.set(hex(is64 ? '4889' : '807c'), 0x200);
    bytes.set(materialize(is64 ? '53565755488D35........488DBE........57' : '60BE........8DBE........57'), 0x200 + shift);
    text(bytes, 0x40, '$Id: UPX 3.96');
    const hit = detect(bytes, parsePE(bytes)).find(hit => hit.family === 'UPX');
    assert.equal(hit?.version, '3.96'); assert.equal(hit.evidence[0].offset, 0x200 + shift);
    put32(bytes, 0x98 + (is64 ? 112 : 96) + 14 * 8, 0x1000);
    assert.deepEqual(detect(bytes, parsePE(bytes)), [], '.NET is excluded');
  }
  const old = minimalPE(); old.set(materialize('60e8000000005883e8..508db8........578db0........83cd..31db9090909001db75'), 0x200);
  assert.equal(detect(old, parsePE(old))[0].version, '0.70');
  const heuristic = minimalPE(); heuristic.fill(0, 0x178, 0x180); text(heuristic, 0x178, '.aspack');
  assert.deepEqual(detect(heuristic, parsePE(heuristic)).map(({ family, confidence, source }) => ({ family, confidence, source })), [{ family: 'ASPack', confidence: 'low', source: 'section-heuristic' }]);
  const markerOnly = minimalPE(); text(markerOnly, 0x40, '$Id: UPX 3.96');
  assert.deepEqual(detect(markerOnly, parsePE(markerOnly)), []);
});

test('REGRESSION: MPRESS DOS version includes the last byte of the 0x1f0..0x1ff window', () => {
  const bytes = minimalPE(); text(bytes, 0x2e, 'Win32 .EXE.\r\n');
  bytes.fill(0x20, 0x1f0, 0x200); text(bytes, 0x1fb, 'v2.19');
  assert.equal(detect(bytes, parsePE(bytes)).find(hit => hit.family === 'MPRESS')?.version, '2.19');
});

test('REGRESSION: entry-point signatures cannot continue through unmapped overlay bytes', () => {
  for (const [family, pattern, is64] of [
    ['FSG', fsgDataset[0].pattern, false],
    ['UPX', '60BE........8DBE........57', false],
    ['UPX', '53565755488D35........488DBE........57', true],
  ]) {
    const bytes = minimalPE({ is64, overlay: 64 });
    put32(bytes, 0xa8, 0x11ff); bytes.set(materialize(pattern), 0x3ff);
    const pe = parsePE(bytes);
    assert.equal(pe.rvaToOffset(0x11ff, pattern.length / 2), null);
    assert.equal(detect(bytes, pe).some(hit => hit.family === family), false, family);
  }
});

test('core analysis is serializable, non-mutating, and separates research from unpack support', async () => {
  const bytes = minimalPE(), original = bytes.slice();
  const result = await analyze(bytes, 'x'.repeat(300));
  assert.equal(result.file.sha256, digest(bytes)); assert.equal(result.file.name.length, 256);
  assert.equal(result.file.size, bytes.length); assert.deepEqual(result.candidates, []);
  assert.deepEqual(result.detections, []); assert.equal(result.pe.rvaToOffset, undefined);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), result); assert.deepEqual(bytes, original);
  assert.deepEqual(await execute('analyze', bytes), await analyze(bytes));
  const caps = capabilities();
  assert.equal(caps.detection.fullEngine, false); assert.equal(caps.detection.commit, manifest.commit);
  assert.deepEqual(caps.limits, { inputBytes: MAX_INPUT, outputBytes: MAX_OUTPUT });
  assert.deepEqual(caps.unpackers.map(item => item.id), ['mpress-pe32-lzmat', 'fsg-pe32', 'upx-pe32-nrv', 'nspack-pe32', 'petite-22-pe32']);
  assert.ok(caps.unpackers.every(item => typeof item.runtimeVerified === 'boolean' && item.status === 'experimental'));
  assert.equal(caps.unpackers.filter(item => item.runtimeVerified).length, 2); // mpress/fsg accepted on a real machine; the upx-nrv analysis path stays false
  assert.equal(caps.catalog.find(item => item.id === 'fsg').stage, 'experimental');
  assert.deepEqual(caps.catalog.find(item => item.id === 'fsg').outputKinds, ['rebuilt-pe']);
  assert.equal(DIE_SCOPE.engine, 'die-rule-subset-js');
  await assert.rejects(unpack(bytes), coded('unsupported-variant'));
  await assert.rejects(unpack(bytes, 'fsg'), coded('unknown-engine'));
  await assert.rejects(execute('run', bytes), coded('unknown-operation'));
});
