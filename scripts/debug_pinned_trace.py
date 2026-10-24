import socket
import sys
import threading

sys.path.insert(0, "tests")
sys.path.insert(0, ".")
import httpx  # noqa: E402
from httpcore._backends.sync import SyncBackend  # noqa: E402

orig_connect = SyncBackend.connect_tcp


def traced_connect(self, host, port, *a, **kw):
    print(f"[dial] {host}:{port} (type={type(host).__name__})")
    return orig_connect(self, host, port, *a, **kw)


SyncBackend.connect_tcp = traced_connect

from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *a):
        pass


srv = HTTPServer(("127.0.0.1", 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
print("server on", port)

import httpcore  # noqa: E402
from app.adapters.pinned import build_pinned_backend  # noqa: E402

backend_cls = build_pinned_backend({"local-model.test": "127.0.0.1"})
pool = httpcore.ConnectionPool(network_backend=backend_cls())
transport = httpx.HTTPTransport()
transport._pool = pool
client = httpx.Client(base_url=f"http://local-model.test:{port}", transport=transport,
                      follow_redirects=False, timeout=httpx.Timeout(5))
try:
    r = client.get("/")
    print("status:", r.status_code, r.text[:40])
except Exception as e:
    print("FAILED:", type(e).__name__, str(e)[:150])
srv.shutdown()
