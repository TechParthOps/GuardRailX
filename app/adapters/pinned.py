"""Connection-time destination enforcement (Phase 4).

validate_endpoint_url() resolves DNS and checks policy, but the HTTP client
performs a SECOND resolution at connect time — a DNS-rebinding TOCTOU gap.
This module closes it: the resolved, policy-validated IP is PINNED into the
transport, so the client dials the validated address directly while TLS SNI
and certificate verification still use the original hostname.

Boundary summary:
  1. Scheme/userinfo/fragment policy            (netguard rules)
  2. Administrator allowlist + credential host binding
  3. DNS resolution -> every resolved IP policy-checked -> ONE pinned IP
  4. Connect-time dial of the pinned IP (no second DNS lookup possible)
  5. Redirects: never auto-followed; each hop re-validated and re-pinned
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpcore
import httpx

from app.adapters.netguard import (CREDENTIAL_TRUSTED_HOSTS, EndpointPolicyError,
                                   _ip_is_forbidden)


def validate_and_pin(url: str, *, allow_local: bool, allowed_hosts: list[str],
                     credential_env: str | None = None) -> tuple[str, str, str]:
    """Full validation + DNS resolution. Returns (normalized_base_url, host, pinned_ip).

    Raises EndpointPolicyError on any policy violation, unresolvable host, or
    forbidden destination IP. IPv4-mapped IPv6 addresses are unwrapped before
    policy checks.
    """
    from app.adapters.netguard import validate_endpoint_policy
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise EndpointPolicyError("invalid URL") from exc
    host = validate_endpoint_policy(url, allowed_hosts=allowed_hosts,
                                    credential_env=credential_env)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EndpointPolicyError(f"endpoint host '{host}' cannot be resolved") from exc

    validated: list[str] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if _ip_is_forbidden(ip, allow_local):
            raise EndpointPolicyError(
                "endpoint resolves to a forbidden address (private/loopback/metadata)")
        if str(ip) not in validated:
            validated.append(str(ip))
    if not validated:
        raise EndpointPolicyError(f"endpoint host '{host}' has no usable addresses")
    return url.rstrip("/"), host, validated[0]


def build_pinned_backend(pin_map: dict[str, str]):
    """Return a backend class whose connect_tcp dials the pinned IP for the
    pinned hostname. TLS server_hostname is derived by httpcore from the
    origin host, so SNI and certificate verification are unaffected."""
    from httpcore._backends.sync import SyncBackend

    class PinnedBackend(SyncBackend):
        def __init__(self):
            super().__init__()
            self.dialed: list[tuple[str, str, int]] = []  # (requested_host, dialed_ip, port)

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            dial = pin_map.get(host, host)
            stream = super().connect_tcp(dial, port, timeout=timeout,
                                         local_address=local_address,
                                         socket_options=socket_options)
            self.dialed.append((host, dial, port))
            return stream

    return PinnedBackend


def pinned_client(base_url: str, *, headers: dict | None = None, timeout: httpx.Timeout,
                  allow_local: bool, allowed_hosts: list[str],
                  credential_env: str | None = None) -> tuple[httpx.Client, str]:
    """Build an httpx.Client PINNED to the validated IP for base_url's host.

    DNS is resolved exactly once, here, under the full endpoint policy.
    Returns (client, pinned_ip). Redirects are never auto-followed.

    Implementation note: httpx's HTTPTransport does not expose httpcore's
    network_backend, so the httpcore connection pool is constructed directly
    (mirroring HTTPTransport's defaults) with the pinned backend injected.
    A version guard fails closed if the internal layout changes.
    """
    normalized, host, ip = validate_and_pin(base_url, allow_local=allow_local,
                                            allowed_hosts=allowed_hosts,
                                            credential_env=credential_env)
    backend_cls = build_pinned_backend({host: ip})
    try:
        import httpcore
        pool = httpcore.ConnectionPool(ssl_context=httpx.create_ssl_context(),
                                       network_backend=backend_cls())
        transport = httpx.HTTPTransport()
        transport._pool = pool  # noqa: SLF001 — deliberate, version-guarded injection
    except (TypeError, AttributeError) as exc:
        # httpx/httpcore internals changed: fail closed rather than lose the
        # connection-time destination guarantee
        raise EndpointPolicyError(
            "pinned transport unavailable in this httpx/httpcore version; "
            "outbound provider calls are blocked") from exc
    client = httpx.Client(base_url=normalized, headers=headers or {}, timeout=timeout,
                          transport=transport, follow_redirects=False)
    return client, ip
