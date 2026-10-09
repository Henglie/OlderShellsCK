// Research bytes only: never execute these PE files. Not bundled/distributed.
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

export const revision = '160baa9447c91d53b75e5e108b196d389fa0b06e';
export const fixtures = Object.freeze([
  { file: 'lab18-02.bin', path: 'Sample/FSG/Lab18-02.exe', size: 4752, sha256: '7983a582939924c70e3da2da80fd3352ebc90de7b8c4c427d484ff4f050f0aec', blob: '8fd9bc85ae1efbc4c52cfb7b78f4aa3163914041' },
  { file: 'fsg131.bin', path: 'Sample/FSG/unpackme- FSG 1.31 - dulek.exe', size: 160480, sha256: '28bdbc5f4268464845940e0e7c5c473af9cc1562ce573ce7a8050c3da024611b', blob: 'ad68dd233f972924126f3c5ead968670a4b46eec' },
  { file: 'fsg133.bin', path: 'Sample/FSG/unpackme- FSG 1.33 - dulek.exe', size: 160432, sha256: '31889f7e66102544c199eb1fe3454641accf7844909b4252e9d9076b4a5803b1', blob: '2ce74d981ceeb770e69e1129e2ff1c4f5e817593' },
  { file: 'golden131.bin', path: 'Tests/UnpackedSample/FSG/unpacked_unpackme- FSG 1.31 - dulek.exe', size: 565248, sha256: '91b9912775aca11b09633fb4913032900ac5fac56571db9021fa8786150f7df0', blob: 'e02b426d2d264fb91cf9cad32e24af5e591b2116' },
  { file: 'golden133.bin', path: 'Tests/UnpackedSample/FSG/unpacked_unpackme- FSG 1.33 - dulek.exe', size: 565248, sha256: '717b82d5f602b7001720223cfbf2f2366a3680346ea146e06bf7b3be9d9cf6ed', blob: 'e4faa6b9d1139f59614a423ee7fc7084f53ae2a8' },
].map(item => Object.freeze({ ...item, url: `https://raw.githubusercontent.com/unipacker/unipacker/${revision}/${item.path.split('/').map(encodeURIComponent).join('/')}` })));

async function download(item) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const response = await fetch(item.url, { signal: AbortSignal.timeout(60000) });
      if (!response.ok) throw new Error(`${item.file}: HTTP ${response.status}`);
      // Fixed tiny corpus; cap the response while streaming, before buffering.
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > item.size) throw new Error(`${item.file}: size mismatch`);
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    } catch (error) {
      if (attempt === 2) throw error;
      await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
    }
  }
}

export async function fetchFixtures(verifyOnly = false) {
  const root = new URL('../test-results/fixtures/fsg/', import.meta.url);
  await mkdir(root, { recursive: true });
  for (const item of fixtures) {
    let bytes;
    if (verifyOnly) bytes = await readFile(new URL(item.file, root));
    else bytes = await download(item);
    const digest = createHash('sha256').update(bytes).digest('hex');
    const blob = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    if (bytes.length !== item.size || digest !== item.sha256 || blob !== item.blob) throw new Error(`${item.file}: integrity mismatch`);
    if (!verifyOnly) await writeFile(new URL(item.file, root), bytes);
    console.log(`${item.file}: ${bytes.length} bytes SHA-256 ${digest}`);
  }
  if (!verifyOnly) await writeFile(new URL('manifest.json', root), JSON.stringify({
    repository: 'https://github.com/unipacker/unipacker', revision,
    usage: 'Read-only research fixtures; upstream repository GPL-2.0. Sample rights are separate; excluded from source/distribution. Never execute.',
    fixtures,
  }, null, 2) + '\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await fetchFixtures(process.argv.includes('--verify'));
