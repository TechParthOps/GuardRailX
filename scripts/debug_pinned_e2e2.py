import socket
import sys
import threading

sys.path.insert(0, "tests")
sys.path.insert(0, ".")
import httpx  # noqa: E402
from httpcore._backends.sync import SyncBackend  # noqa: E402

orig_connect = SyncBackend.connect_tcp


def traced(self, host, port, *a, **kw):
    print(f"[dial] {host}:{port}")
    return orig_connect(self, host, port, *a, **kw)


SyncBackend.connect_tcp = traced

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

import test_netguard_transport as T  # noqa: E402

dns = T.FakeDNS({"local-model.test": [T.LOOPBACK]})

real_setattr = setattr


def fake_getaddrinfo(host, port_, *a, **k):
    dns.calls.append(host)
    ip = dns.answers.get(host, [T.PUBLIC])[0]
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(fam, socket.SOCK_STREAM, 6, "", (ip, port_))]


socket.getaddrinfo = fake_getaddrinfo

from app.adapters.pinned import pinned_client  # noqa: E402

client, ip = pinned_client(f"http://local-model.test:{port}", timeout=httpx.Timeout(5),
                           allow_local=True, allowed_hosts=["local-model.test"],
                           credential_env=None)
print("pinned:", ip)
import socket as _s
try:
    _sock = _s.create_connection(("127.0.0.1", port), timeout=3)
    print("raw dial OK"); _sock.close()
except Exception as _e:
    print("raw dial failed:", _e)
try:
    r = client.get("/")
    print("status:", r.status_code, r.text[:40])
except Exception as e:
    print("FAILED:", type(e).__name__, str(e)[:150])
srv.shutdown()
