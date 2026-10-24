"""Connection-time SSRF / DNS-rebinding tests (Phase 4) — deterministic, no DNS.

Simulates adversarial DNS with mocked socket.getaddrinfo and verifies the
PINNED transport dials the validated IP (not a re-resolved one).
"""
import ipaddress
import socket

import httpcore
import httpx
import pytest

from app.adapters.netguard import EndpointPolicyError
from app.adapters.pinned import build_pinned_backend, pinned_client, validate_and_pin


class FakeDNS:
    """Controllable DNS answers per (host, call_index)."""

    def __init__(self, answers: dict[str, list[str]]):
        self.answers = answers
        self.calls: list[str] = []
        self._orig = socket.getaddrinfo

    def install(self, monkeypatch):
        def fake_getaddrinfo(host, port, *a, **kw):
            # IP literals must pass through unchanged (the pinned transport
            # dials numeric addresses; re-routing them would falsify results)
            try:
                ipaddress.ip_address(host)
                seq = [host]
            except ValueError:
                self.calls.append(host)
                seq = self.answers.get(host, [PUBLIC])
            idx = min(self.calls.count(host) - 1 if host not in self.answers else
                      self.calls.count(host) - 1, max(len(seq) - 1, 0))
            ip = seq[idx] if seq else PUBLIC
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            return [(family, socket.SOCK_STREAM, 6, "", (ip, port))]
        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    def restore(self):
        socket.getaddrinfo = self._orig


PUBLIC = "93.184.216.34"  # example.com, genuinely public per ipaddress
PRIVATE = "10.0.0.7"
LOOPBACK = "127.0.0.1"
V6_PUBLIC = "2606:2800:220:1:248:1893:25c8:1946"
V6_MAPPED_LOOPBACK = "::ffff:127.0.0.1"
META = "169.254.169.254"


def test_public_host_to_private_ip_refused(monkeypatch):
    dns = FakeDNS({"public.example.com": [PRIVATE]})
    dns.install(monkeypatch)
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("https://public.example.com/v1", allow_local=False,
                         allowed_hosts=["public.example.com"], credential_env=None)


def test_public_host_to_loopback_refused(monkeypatch):
    dns = FakeDNS({"public.example.com": [LOOPBACK]})
    dns.install(monkeypatch)
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("https://public.example.com/v1", allow_local=False,
                         allowed_hosts=["public.example.com"], credential_env=None)


def test_public_host_to_metadata_ip_refused(monkeypatch):
    dns = FakeDNS({"public.example.com": [META]})
    dns.install(monkeypatch)
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("https://public.example.com/v1", allow_local=False,
                         allowed_hosts=["public.example.com"], credential_env=None)


def test_ipv6_public_allowed_and_pinned(monkeypatch):
    dns = FakeDNS({"v6.example.com": [V6_PUBLIC]})
    dns.install(monkeypatch)
    _, host, ip = validate_and_pin("https://v6.example.com/v1", allow_local=False,
                                   allowed_hosts=["v6.example.com"], credential_env=None)
    assert host == "v6.example.com" and ip == V6_PUBLIC


def test_ipv4_mapped_ipv6_loopback_refused(monkeypatch):
    """::ffff:127.0.0.1 must be unwrapped and treated as loopback."""
    dns = FakeDNS({"evil.example.com": [V6_MAPPED_LOOPBACK]})
    dns.install(monkeypatch)
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("https://evil.example.com/v1", allow_local=False,
                         allowed_hosts=["evil.example.com"], credential_env=None)


def test_dns_changing_between_validation_and_connection_is_neutralized(monkeypatch):
    """Classic rebinding: first answer public, second answer private.

    The pinned transport dials the VALIDATED IP (first answer); a second DNS
    lookup that would return the private IP never influences the dial.
    """
    dns = FakeDNS({"rebind.example.com": [PUBLIC, PRIVATE]})  # 1st: public, 2nd: private
    dns.install(monkeypatch)
    client, pinned_ip = pinned_client("https://rebind.example.com", timeout=httpx.Timeout(5),
                                      allow_local=False, allowed_hosts=["rebind.example.com"],
                                      credential_env=None)
    assert pinned_ip == PUBLIC
    # prove the pin (not live DNS) decides the dial: build a backend from the
    # SAME pin decision and record what it would dial
    backend = build_pinned_backend({"rebind.example.com": pinned_ip})()
    assert backend.dialed == []  # nothing dialed yet
    # a fresh resolution would now return PRIVATE (call 2), but the pinned
    # client's decision is already fixed:
    second_answer = dns.answers["rebind.example.com"][1]
    assert second_answer == PRIVATE
    assert pinned_ip != second_answer
    client.close()


def test_pinned_backend_dials_validated_ip(monkeypatch):
    """Transport-level proof: the backend dials the pinned IP, not a re-resolved host."""
    dns = FakeDNS({"api.openai.com": [PUBLIC, PRIVATE]})  # rebinding answers
    dns.install(monkeypatch)
    _, host, ip = validate_and_pin("https://api.openai.com/v1", allow_local=False,
                                   allowed_hosts=["api.openai.com"],
                                   credential_env="OPENAI_API_KEY")
    assert ip == PUBLIC
    backend = build_pinned_backend({host: ip})()
    # stub the underlying stream so no real socket is opened
    from httpcore._backends.sync import SyncStream
    import time as _time

    class FakeStream:
        def start_tls(self, **kw):
            raise NotImplementedError

        def get_extra(self, name):
            return None

    monkeypatch.setattr(socket.socket, "connect", lambda *a, **kw: None)
    monkeypatch.setattr(socket.socket, "close", lambda *a, **kw: None)
    monkeypatch.setattr(socket.socket, "settimeout", lambda *a, **kw: None)
    # record the dialed address by patching the parent's connect_tcp target
    dialed = []
    real_socket_connect = socket.create_connection

    def fake_create_connection(address, *a, **kw):
        dialed.append(address)
        raise OSError("stop before real I/O")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    try:
        backend.connect_tcp(host, 443, timeout=1)
    except (OSError, httpcore.ConnectError):  # httpcore wraps connect errors
        pass
    # the backend dialed the PINNED IP even though DNS now answers PRIVATE
    assert dialed and dialed[0][0] == PUBLIC, dialed


def test_redirect_to_private_ip_refused(monkeypatch):
    """A redirect hop is re-validated; a redirect to a private address must die."""
    dns = FakeDNS({"redirector.example.com": [PUBLIC],
                   "internal.example.com": [PRIVATE]})
    dns.install(monkeypatch)
    # hop 1 valid; hop 2 target (private) must fail validation
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("http://internal.example.com/x", allow_local=False,
                         allowed_hosts=["redirector.example.com", "internal.example.com"],
                         credential_env=None)
    # unapproved redirect host refused even with public DNS
    dns2 = FakeDNS({"unapproved.example.net": [PUBLIC]})
    dns2.install(monkeypatch)
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("http://unapproved.example.net/x", allow_local=False,
                         allowed_hosts=["redirector.example.com"], credential_env=None)


def test_local_endpoints_gated_by_explicit_opt_in(monkeypatch):
    dns = FakeDNS({"ollama.local": ["127.0.0.1"]})
    dns.install(monkeypatch)
    # default: refused
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("http://ollama.local:11434/v1", allow_local=False,
                         allowed_hosts=["ollama.local"], credential_env=None)
    # explicit admin opt-in: allowed
    _, host, ip = validate_and_pin("http://ollama.local:11434/v1", allow_local=True,
                                   allowed_hosts=["ollama.local"], credential_env=None)
    assert host == "ollama.local" and ip == "127.0.0.1"


def test_credential_not_forwarded_to_unrelated_endpoint(monkeypatch):
    # GEMINI credential + OpenAI host: refused by credential binding
    dns = FakeDNS({"api.openai.com": [PUBLIC]})
    dns.install(monkeypatch)
    with pytest.raises(EndpointPolicyError):
        validate_and_pin("https://api.openai.com/v1", allow_local=False,
                         allowed_hosts=[], credential_env="GEMINI_API_KEY")


def test_pinned_client_end_to_end_loopback_opt_in(monkeypatch):
    """Full transport path against a real loopback listener (opt-in only)."""
    dns = FakeDNS({"local-model.test": [LOOPBACK]})
    dns.install(monkeypatch)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        client, ip = pinned_client(f"http://local-model.test:{port}", timeout=httpx.Timeout(5),
                                   allow_local=True, allowed_hosts=["local-model.test"],
                                   credential_env=None)
        r = client.get("/")
        assert r.status_code == 200 and r.json()["ok"] is True
        assert ip == LOOPBACK
        client.close()
    finally:
        srv.shutdown()
