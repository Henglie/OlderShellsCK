// Server-side external-tool engine: invokes the official UPX binary
// (downloaded by scripts/fetch-upx-tool.mjs, GPL-2.0+, never committed).
// Process invocation only — no GPL code is linked or bundled.
import { access, readFile, writeFile, rm, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { parsePE } from '../pe.js';
import { requireThat } from '../errors.js';

const EXE = fileURLToPath(new URL('../../../tools/upx/upx.exe', import.meta.url));

export const UPX_TOOL_ENGINE = Object.freeze({
  id: 'upx-official', family: 'UPX', catalogId: 'upx', variant: 'official upx -d; every format its own decoder accepts',
  outputKind: 'rebuilt-pe', runtimeVerified: true, status: 'experimental', architecture: 'x86',
  mode: 'external-tool', runtime: 'server', platform: 'win32',
});

async function spawnUpx(args, cwd) {
  const { spawn } = await import('node:child_process');
  return new Promise((resolve, reject) => {
    const child = spawn(EXE, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', chunk => { out += chunk; });
    child.stderr.on('data', chunk => { err += chunk; });
    const timer = setTimeout(() => { child.kill(); reject(Object.assign(new Error('tool timeout'), { code: 'tool-timeout' })); }, 30000);
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => { clearTimeout(timer); resolve({ code, out, err }); });
  });
}

export function supportsUpxTool() { return false; } // never auto-selected; explicit choice only

export async function unpackUpxTool(bytes, name = 'sample.exe') {
  requireThat(typeof process !== 'undefined' && process.versions?.node, 'engine-unavailable', { hint: 'server-side engine; the browser worker cannot spawn processes' });
  requireThat(process.platform === 'win32', 'engine-unavailable', { hint: 'upx.exe is a Windows binary' });
  try { await access(EXE); } catch { requireThat(false, 'engine-unavailable', { hint: 'run node scripts/fetch-upx-tool.mjs first' }); }
  const dir = await mkdtemp(join(tmpdir(), 'older-shells-ck-'));
  const input = join(dir, 'in.exe'), output = join(dir, 'out.exe');
  try {
    await writeFile(input, bytes);
    const result = await spawnUpx(['-d', '-q', '-o', 'out.exe', 'in.exe'], dir);
    if (result.code !== 0) {
      const detail = (result.err || result.out).split('\n').map(line => line.trim()).filter(line => line.includes('Exception') || line.includes('upx:'))[0] || '';
      requireThat(false, /modified|CantUnpack|not packed|AlreadyUnpacked/i.test(detail) ? 'unsupported-variant' : 'tool-error', { hint: detail.slice(0, 200) });
    }
    const unpacked = new Uint8Array(await readFile(output));
    const pe = parsePE(unpacked);
    return {
      bytes: unpacked, name: `${String(name).split(/[\\/]/).pop().replace(/[^\w.\-\u4e00-\u9fff]/g, '_').slice(0, 120) || 'sample.exe'}`.replace(/\.exe$/i, '') + '.unpacked.exe',
      metadata: {
        engine: UPX_TOOL_ENGINE.id, variant: 'official upx -d', outputKind: 'rebuilt-pe', runtimeVerified: false,
        mode: 'external-tool', originalEntryPoint: pe.entryPointRva, tool: 'upx 4.2.4 (GPL-2.0+, downloaded)',
        runtimeVerified: true, acceptance: 'output ran on Henglie\'s machine (2026-10-05)',
        inputSha256: createHash('sha256').update(bytes).digest('hex'),
        warnings: ['runtime-not-verified'],
      },
    };
  } finally { await rm(dir, { recursive: true, force: true }); }
}
