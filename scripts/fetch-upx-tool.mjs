// Downloads the official UPX binary release used by the server-side
// external-tool engine. GPL-2.0 licensed; never committed to the repository.
import { mkdir, writeFile, readFile, access, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
const run = promisify(execFile);

const VERSION = process.env.UPX_VERSION || '4.2.4';
const DOWNLOAD_URL = `https://github.com/upx/upx/releases/download/v${VERSION}/upx-${VERSION}-win64.zip`;
const DIR = new URL('../tools/upx/', import.meta.url);
const dir = fileURLToPath(DIR);
const EXE = new URL('upx.exe', DIR);
// sha256 of the official v4.2.4 win64 zip, recorded from the first
// github.com/upx/upx release download; verified on every later run
const PINNED_SHA256 = '22e9ef20e4c72aad85e32c71cbc9c086436c179456382aa75c0c24868456a671';

async function download() {
  const response = await fetch(DOWNLOAD_URL, { redirect: 'follow' });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

await mkdir(DIR, { recursive: true });
const zipPath = `${dir}upx.zip`;
try { await access(EXE); } catch {
  let bytes, lastError;
  try { bytes = await readFile(zipPath); } catch {}
  if (bytes) console.log('reusing partial download upx.zip');
  for (let attempt = 1; attempt <= 6 && !bytes; attempt++) {
    try { bytes = await download(); } catch (error) { lastError = error; console.log(`attempt ${attempt} failed: ${error.cause?.code || error.message}`); await new Promise(resolve => setTimeout(resolve, attempt * 2000)); }
  }
  if (!bytes) throw lastError;
  await writeFile(zipPath, bytes);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (PINNED_SHA256 && sha256 !== PINNED_SHA256) throw new Error(`sha256 mismatch: got ${sha256}; update PINNED_SHA256 in this script after verifying the release`);
  await run('tar', ['-xf', zipPath, '-C', dir]);
  const { rename } = await import('node:fs/promises');
  await rename(`${dir}upx-${VERSION}-win64${'\\'}upx.exe`, `${dir}upx.exe`);
  for (const extra of ['LICENSE', 'COPYING']) { try { await rename(`${dir}upx-${VERSION}-win64${'\\'}${extra}`, `${dir}${extra}`); } catch {} }
  await rm(`${dir}upx-${VERSION}-win64`, { recursive: true, force: true });
  await rm(`${dir}upx-${VERSION}-win64`, { recursive: true, force: true });
  await rm(zipPath, { force: true });
  console.log(`downloaded upx ${VERSION}, zip sha256 ${sha256}`);
}
const exe = await readFile(EXE);
const manifest = { version: VERSION, source: DOWNLOAD_URL, exeSha256: createHash('sha256').update(exe).digest('hex'), license: 'GPL-2.0-or-later (with special exception for the decompressor); obtained by download, never committed' };
await writeFile(new URL('manifest.json', DIR), JSON.stringify(manifest, null, 2) + '\n');
console.log(JSON.stringify(manifest, null, 2));
