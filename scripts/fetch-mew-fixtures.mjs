// Pins the MEW evidence sample. Static bytes only; never executed.
// The MEW 11 SE loader requires an LZMA1 range-coder decoder (props 0x5E,
// lc=4/lp=0/pb=2, no end marker) which this project has not yet ported;
// no MEW engine is registered, so this fixture documents detection scope.
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const commit = '160baa9447c91d53b75e5e108b196d389fa0b06e';
const file = {
  local: 'lbop20-mew.bin', remote: 'Sample/MEW/lbop20_MEW.exe', size: 34185,
  sha256: '42e83208184d5ef0ebfced4347540b4629fe2d6c901295dd0dc9eb18a5b96af5',
};
const base = `https://raw.githubusercontent.com/unipacker/unipacker/${commit}/`;
const dir = new URL('../test-results/fixtures/mew/', import.meta.url);
await mkdir(dir, { recursive: true });
const destination = new URL(file.local, dir);
let bytes;
try { bytes = Buffer.from(await readFile(destination)); }
catch {
  for (let attempt = 1; attempt <= 6; attempt++) {
    try { const response = await fetch(base + file.remote); if (!response.ok) throw new Error(`HTTP ${response.status}`); bytes = Buffer.from(await response.arrayBuffer()); break; }
    catch (error) { if (attempt === 6) throw error; await new Promise(resolve => setTimeout(resolve, attempt * 1500)); }
  }
  await writeFile(destination, bytes);
}
if (bytes.length !== file.size) throw new Error(`${file.local}: size ${bytes.length} != ${file.size}`);
const sha256 = createHash('sha256').update(bytes).digest('hex');
if (sha256 !== file.sha256) throw new Error(`${file.local}: sha256 ${sha256} != ${file.sha256}`);
await writeFile(new URL('manifest.json', dir), JSON.stringify({ repository: 'unipacker/unipacker', commit, note: 'static bytes only; never executed; detection-scope evidence until an LZMA1 decoder is vetted', files: [{ ...file, url: base + file.remote }] }, null, 2) + '\n');
console.log('Verified MEW evidence fixture (detection scope only)');
