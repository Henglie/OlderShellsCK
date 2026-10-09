#!/usr/bin/env python3
"""Serve only the built static site on loopback; no third-party dependencies."""
import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote
import webbrowser

ROOT = Path(__file__).resolve().parent / 'dist'


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, '.js': 'text/javascript', '.wasm': 'application/wasm'}

    def do_GET(self):
        host = self.headers.get('Host', '')
        port = self.server.server_address[1]
        allowed = (f'127.0.0.1:{port}', f'localhost:{port}')
        origin = self.headers.get('Origin')
        if host not in allowed or (origin and origin not in tuple(f'http://{h}' for h in allowed)):
            self.send_error(403)
            return
        path = unquote(self.path.split('?', 1)[0])
        target = Path(self.translate_path(path)).resolve()
        if not target.is_relative_to(ROOT.resolve()) or '\\' in path or ':' in path or any(part.startswith('.') for part in path.split('/')):
            self.send_error(404)
            return
        if target.is_dir() and not (target / 'index.html').is_file():
            self.send_error(404)
            return
        super().do_GET()

    def do_HEAD(self):
        self.send_error(405)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cross-Origin-Opener-Policy', 'same-origin')
        self.send_header('Cross-Origin-Embedder-Policy', 'require-corp')
        super().end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8787)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    if not (ROOT / 'index.html').is_file():
        parser.exit(1, 'Run npm ci && npm run build first. / 请先执行 npm ci && npm run build\n')
    server = ThreadingHTTPServer(('127.0.0.1', args.port), partial(Handler, directory=str(ROOT)))
    url = f'http://127.0.0.1:{server.server_address[1]}'
    print(f'OlderShellsCK {url} (static Web; Node server required for HTTP API)', flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
