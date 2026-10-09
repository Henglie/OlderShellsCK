import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

test('Python launcher serves only built static files on loopback', async t => {
  try { await access(new URL('../dist/index.html', import.meta.url)); } catch { t.skip('Run npm run build to verify the optional launcher'); return; }
  const script = fileURLToPath(new URL('../点我启动.py', import.meta.url));
  const child = spawn(process.platform === 'win32' ? 'py' : 'python3', [...(process.platform === 'win32' ? ['-3.11'] : []), script, '--port', '0', '--no-browser'], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PYTHONIOENCODING: 'utf-8' } });
  t.after(() => child.kill());
  const url = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Python startup timeout')), 10000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Python exit ${code}`)); });
    let output = '';
    child.stdout.on('data', data => { output += data; const match = output.match(/http:\/\/127\.0\.0\.1:\d+/); if (match) { clearTimeout(timer); resolve(match[0]); } });
  });
  const response = await fetch(url);
  assert.equal(response.status, 200); assert.match(await response.text(), /app\.js/);
  assert.equal(response.headers.get('cross-origin-opener-policy'), 'same-origin');
  for (const path of ['/PROGRESS.md', '/src/core/index.js', '/资料/archive-inventory.json', '/api/v1/capabilities', '/licenses/']) assert.equal((await fetch(url + path)).status, 404, path);
  assert.equal((await fetch(url + '/worker.js')).headers.get('content-type'), 'text/javascript');
  assert.equal((await fetch(url, { headers: { Origin: 'https://example.com' } })).status, 403);
});
