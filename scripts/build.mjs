import { build } from 'esbuild';
import { mkdir, copyFile, readFile, writeFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const root = new URL('../', import.meta.url), output = new URL('dist/', root);
await mkdir(output, { recursive: true });
const copy = async (from, to) => {
  const target = new URL(to, output); await mkdir(new URL('.', target), { recursive: true }); await copyFile(new URL(from, root), target);
};
await build({ absWorkingDir: fileURLToPath(root), entryPoints: { app: 'src/web/app.js', worker: 'src/web/worker.js' }, bundle: true,
  outdir: fileURLToPath(output), format: 'esm', target: ['es2022'], minify: true, legalComments: 'linked', sourcemap: false, logLevel: 'info' });
for (const name of ['index.html', 'styles.css', 'icon.svg']) await copy(`src/web/${name}`, name);
for (const name of ['README.md', 'README.en.md', 'LICENSE', 'NOTICE', 'CHANGELOG.md', 'docs/API.md', 'docs/ARCHITECTURE.md', 'docs/research/die-and-packers.md', 'docs/research/archive-inventory.md', 'docs/research/gui-unpackers-reverse.md', 'docs/research/fsg-implementation.md', 'docs/research/upx-implementation.md', 'docs/research/aspack-implementation.md', 'docs/research/mew-implementation.md', 'licenses/retdec-MIT.txt', 'licenses/xstaticunpacker-MIT.txt']) await copy(name, name);
await copy('vendor/die/LICENSE', 'licenses/die-MIT.txt');
await copy('vendor/die/manifest.json', 'licenses/die-source-manifest.json');
const browserPackages = ['@material/web', '@material/material-color-utilities', 'lit', 'lit-html', 'lit-element', '@lit/reactive-element', '@lit/context', '@lit-labs/ssr-dom-shim', 'tslib'];
const licenses = [];
for (const name of browserPackages) {
  const pkg = JSON.parse(await readFile(new URL(`node_modules/${name}/package.json`, root), 'utf8'));
  const names = await readdir(new URL(`node_modules/${name}/`, root));
  const file = names.find(value => /^license(?:\.\w+)?$/i.test(value));
  if (!file && name !== '@lit-labs/ssr-dom-shim') throw new Error(`Missing dependency license: ${name}`);
  const dest = `licenses/${name.replaceAll('/', '-').replace('@', '')}.txt`;
  await copy(file ? `node_modules/${name}/${file}` : 'NOTICE', dest);
  licenses.push({ name, version: pkg.version, license: pkg.license, file: dest });
}
await writeFile(new URL('licenses/dependencies.json', output), JSON.stringify(licenses, null, 2));
console.log('Built static site in dist/ (explicit asset and license allowlist).');
