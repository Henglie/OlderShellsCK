import { createServer } from 'node:http';
import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, sep, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capabilities } from '../core/index.js';
import './engines-server.js';
import { AnalysisError, serializeError } from '../core/errors.js';
import { decodeRequest, encodeResult, MAX_JSON } from './transport.js';
import { MAX_CONCURRENCY, runJob } from './jobs.js';

const defaultRoot = fileURLToPath(new URL('../../dist/', import.meta.url));
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.txt': 'text/plain; charset=utf-8', '.md': 'text/plain; charset=utf-8' };
const json = (response, status, body) => { response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); response.end(JSON.stringify(body)); };

async function readJson(request) {
  if (Number(request.headers['content-length']) > MAX_JSON) throw new AnalysisError('input-size-limit');
  const chunks = []; let length = 0;
  // Keep the socket alive long enough to deliver a 413 for chunked uploads too.
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    length += chunk.length;
    if (length > MAX_JSON) throw new AnalysisError('input-size-limit');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new AnalysisError('invalid-json'); }
}

export function createAppServer({ root = defaultRoot, jobRunner = runJob, maximum = MAX_CONCURRENCY } = {}) {
  if (!Number.isInteger(maximum) || maximum < 1) throw new TypeError('invalid-request-limit');
  let active = 0;
  const server = createServer(async (request, response) => {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; worker-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    try {
      const port = server.address()?.port;
      const allowed = [`127.0.0.1:${port}`, `localhost:${port}`];
      if (!allowed.includes(request.headers.host) || (request.headers.origin && !allowed.some(host => request.headers.origin === `http://${host}`))) {
        return json(response, 403, { error: { code: 'forbidden-origin' } });
      }
      if (request.headers['sec-fetch-site'] === 'cross-site') return json(response, 403, { error: { code: 'forbidden-origin' } });
      let pathname;
      try { pathname = decodeURIComponent(request.url.split('?')[0]); } catch { throw new AnalysisError('invalid-path'); }
      // Check before URL normalization; also exclude Windows separators/ADS.
      if (!pathname.startsWith('/') || pathname.startsWith('//') || /[\\:\x00-\x1f\x7f#]/.test(pathname) || pathname.split('/').some(part => part.startsWith('.'))) {
        return json(response, 404, { error: { code: 'not-found' } });
      }
      if (pathname === '/api/v1/capabilities' && request.method === 'GET') return json(response, 200, capabilities());
      if (['/api/v1/analyze', '/api/v1/unpack'].includes(pathname)) {
        if (request.method !== 'POST') return json(response, 405, { error: { code: 'method-not-allowed' } });
        if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') return json(response, 415, { error: { code: 'json-required' } });
        if (active >= maximum) { request.resume(); return json(response, 503, { error: { code: 'busy' } }); }
        // Bound uploads as well as workers, before buffering or base64 decoding.
        active++;
        try {
          const { bytes, options } = decodeRequest(await readJson(request));
          const result = await jobRunner(pathname.endsWith('/unpack') ? 'unpack' : 'analyze', bytes, options);
          return json(response, 200, encodeResult(result));
        } finally { active--; }
      }
      if (!['GET', 'HEAD'].includes(request.method)) return json(response, 405, { error: { code: 'method-not-allowed' } });
      if (pathname.startsWith('/api/')) return json(response, 404, { error: { code: 'not-found' } });
      const base = await realpath(root);
      const candidate = resolve(base, '.' + (pathname === '/' ? '/index.html' : pathname));
      if (!candidate.startsWith(base + sep)) return json(response, 404, { error: { code: 'not-found' } });
      const actual = await realpath(candidate);
      if (!actual.startsWith(base + sep) || !(await stat(actual)).isFile()) return json(response, 404, { error: { code: 'not-found' } });
      response.writeHead(200, { 'Content-Type': mime[extname(actual)] || 'text/plain; charset=utf-8' });
      response.end(request.method === 'HEAD' ? undefined : await readFile(actual));
    } catch (error) {
      if (response.headersSent) { response.destroy(); return; }
      const missing = ['ENOENT', 'ENOTDIR', 'EINVAL'].includes(error.code);
      const status = missing ? 404 : ({ busy: 503, timeout: 408, 'worker-failed': 500, 'input-size-limit': 413 })[error.code] || (error instanceof AnalysisError ? 400 : 500);
      if (status === 413) { response.setHeader('Connection', 'close'); request.resume(); }
      json(response, status, { error: missing ? { code: 'not-found' } : serializeError(error) });
    }
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 8787);
  const server = createAppServer();
  server.on('error', error => { console.error(error.message); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => console.log(`OlderShellsCK http://127.0.0.1:${server.address().port}`));
}
