// Static data only. Never execute these PE fixtures (Lab18-01 is a malware-lab sample).
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const root = new URL('../test-results/fixtures/upx/', import.meta.url);
const commit = '160baa9447c91d53b75e5e108b196d389fa0b06e';
const fixtures = [
  { path: 'Sample/UPX/lbop20_UPX.exe', file: 'lbop20.upx.bin', size: 38400,
    sha256: 'e844ea038a39d448b7a803196f6aa5eaf8697dc48b3305a9b28d544784029158' },
  { path: 'Sample/UPX/Lab18-01.exe', file: 'lab18-01.upx.bin', size: 13824,
    sha256: '2ac6635a26049d354c0c46243f6451e6594b130745a08c5a99e96a64fbbbec0f' },
  { path: 'Tests/UnpackedSample/UPX/unpacked_lbop20_UPX.exe', file: 'lbop20.golden.bin', size: 176128,
    sha256: '5b8cc03b22d3bf8d00e600300ece15359dc10148d474f988b643c5ae863d0163' },
];
await mkdir(root, { recursive: true });
for (const fixture of fixtures) {
  fixture.url = `https://raw.githubusercontent.com/unipacker/unipacker/${commit}/${fixture.path}`;
  const response = await fetch(fixture.url, { signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${fixture.path}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (bytes.length !== fixture.size || sha256 !== fixture.sha256) throw new Error(`Fixture integrity mismatch: ${fixture.path}`);
  await writeFile(new URL(fixture.file, root), bytes);
  console.log(`${fixture.file}: ${bytes.length} bytes, SHA-256 ${sha256}`);
}
await writeFile(new URL('manifest.json', root), JSON.stringify({
  repository: 'https://github.com/unipacker/unipacker', commit,
  execution: 'never; static data only', redistribution: 'excluded from git and releases', fixtures,
}, null, 2) + '\n');
