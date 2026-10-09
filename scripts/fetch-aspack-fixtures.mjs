// Pins the only reproducible ASPack corpus pair available to this project.
// The packed sample is NOT a supported engine input: none of the six
// XStaticUnpacker-vetted plaintext layouts match it (its push/ret marker sits
// at EP+0x437 and its stub carries no plaintext compB table). It is pinned as
// detection-and-rejection evidence: DIE identifies ASPack and the unpacker
// must refuse it with unsupported-variant rather than guess a layout.
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const commit = '160baa9447c91d53b75e5e108b196d389fa0b06e';
const base = `https://raw.githubusercontent.com/unipacker/unipacker/${commit}/`;
const files = [
  { local: 'aspack-lbop20.bin', remote: 'Sample/ASPack/lbop20_aspack.exe', size: 43520, sha256: 'a7a2f792185842ea20f100f8a0059842bc299a2e5c0318751840fdd38224800a' },
  { local: 'golden-lbop20.bin', remote: 'Tests/UnpackedSample/ASPack/unpacked_lbop20_aspack.exe', size: 176128, sha256: '4de460a6f7658f9c6233c9be3f9be70cf893d2010276c1b5c7521cfc42e15ce7' },
];
const dir = new URL('../test-results/fixtures/aspack/', import.meta.url);
await mkdir(dir, { recursive: true });
const manifest = [];
for (const file of files) {
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
  manifest.push({ ...file, url: base + file.remote, commit });
}
await writeFile(new URL('manifest.json', dir), JSON.stringify({ repository: 'unipacker/unipacker', commit, note: 'static bytes only; never executed; pinned for detection-and-rejection evidence', files: manifest }, null, 2) + '\n');
console.log(`Verified ${files.length} ASPack evidence fixtures (detection-and-rejection only)`);
