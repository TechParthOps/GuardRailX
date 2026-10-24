import socket
import sys
import threading

sys.path.insert(0, "tests")
sys.path.insert(0, ".")
import httpx  # noqa: E402

from test_netguard_transport import FakeDNS, LOOPBACK  # noqa: E402
from app.adapters.pinned import pinned_client, build_pinned_backend  # noqa: E402

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

dns = FakeDNS({"local-model.test": [LOOPBACK]})
dns.install(type("M", (), {"setattr": staticmethod(lambda mod, n, v: setattr(mod, n, v))})())
print("dns patched; resolving once:", socket.getaddrinfo("local-model.test", 80)[0][4])

client, ip = pinned_client(f"http://local-model.test:{port}", timeout=httpx.Timeout(5),
                           allow_local=True, allowed_hosts=["local-model.test"],
                           credential_env=None)
print("pinned to", ip)
try:
    r = client.get("/")
    print("status:", r.status_code, r.text[:40])
except Exception as e:
    print("FAILED:", type(e).__name__, str(e)[:200])
srv.shutdown()
