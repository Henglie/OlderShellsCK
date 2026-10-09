import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import '../src/server/engines-server.js';
import { unpack, capabilities } from '../src/core/index.js';

const exe = fileURLToPath(new URL('../tools/upx/upx.exe', import.meta.url));
let ready = false;
try { await access(exe); ready = process.platform === 'win32'; } catch {}

test('external-tool engine is registered with an explicit route and runtime', { skip: !ready && 'Run node scripts/fetch-upx-tool.mjs on win32 first' }, () => {
  const descriptor = capabilities().unpackers.find(engine => engine.id === 'upx-official');
  assert.ok(descriptor, 'registered server engine appears in capabilities');
  assert.equal(descriptor.mode, 'external-tool');
  assert.equal(descriptor.runtime, 'server');
  assert.equal(descriptor.outputKind, 'rebuilt-pe');
  assert.ok(capabilities().catalog.find(item => item.id === 'upx').engineIds.includes('upx-official'));
});

test('official upx -d rebuilds the pinned UPX fixture', { skip: !ready && 'Run node scripts/fetch-upx-tool.mjs on win32 first' }, async () => {
  const bytes = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.upx.bin', import.meta.url)));
  const result = await unpack(bytes, 'upx-official', 'lbop20.upx.bin');
  assert.equal(String.fromCharCode(...result.bytes.subarray(0, 2)), 'MZ');
  assert.equal(result.metadata.outputKind, 'rebuilt-pe');
  assert.equal(result.metadata.mode, 'external-tool');
  assert.equal(result.metadata.originalEntryPoint, 0x1252);
  assert.match(result.metadata.tool, /^upx /);
  assert.equal(result.report.pe.entryPointRva, 0x1252);
});

test('official upx refuses modified or unpacked inputs with stable error codes', { skip: !ready && 'Run node scripts/fetch-upx-tool.mjs on win32 first' }, async () => {
  const modified = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lab18-01.upx.bin', import.meta.url)));
  await assert.rejects(unpack(modified, 'upx-official', 'lab18-01.upx.bin'), error => error.code === 'unsupported-variant');
  const plain = new Uint8Array(await readFile(new URL('../test-results/fixtures/upx/lbop20.golden.bin', import.meta.url)));
  await assert.rejects(unpack(plain, 'upx-official', 'golden.bin'), error => error.code === 'unsupported-variant' || error.code === 'invalid-pe-header');
});
