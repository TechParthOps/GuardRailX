"""Outbound endpoint security guard (GX-003 fix).

Every provider base_url configured by a user must pass this guard before any
HTTP request is made. Rules:

  * scheme must be http/https (no file://, ftp://, unix://)
  * no userinfo (user:pass@host), no fragments
  * hostname must be admin-allowlisted (GX_ALLOWED_ENDPOINT_HOSTS) OR map to a
    known trusted provider host for the chosen credential
  * loopback / private / link-local / reserved / multicast IPs are REFUSED
    unless the operator explicitly enables GX_ALLOW_LOCAL_ENDPOINTS (for
    local model servers such as Ollama/vLLM)
  * DNS is resolved and every resolved IP is validated (anti-DNS-rebinding)
  * redirects are NOT followed automatically; adapters re-validate each hop
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

# credential env var -> trusted default host
CREDENTIAL_TRUSTED_HOSTS: dict[str, str] = {
    "OPENAI_API_KEY": "api.openai.com",
    "ANTHROPIC_API_KEY": "api.anthropic.com",
    "GEMINI_API_KEY": "generativelanguage.googleapis.com",
    "NVIDIA_API_KEY": "integrate.api.nvidia.com",
}


class EndpointPolicyError(Exception):
    """Raised when a destination violates the endpoint security policy."""


def _ip_is_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                     allow_local: bool) -> bool:
    if ip.is_loopback:
        return not allow_local
    if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return not allow_local
    if ip.is_unspecified:
        return True
    # cloud metadata endpoints (link-local 169.254.169.254 covered above)
    return False


def validate_endpoint_policy(url: str, *, allowed_hosts: list[str],
                             credential_env: str | None = None) -> str:
    """Policy-only validation (NO DNS): scheme, userinfo, fragments, host
    allowlist, credential-to-host binding. Returns the normalized host.

    Used on fast validation paths (target registration, config checks); full
    resolution + IP pinning happens in app.adapters.pinned at connection time.
    """
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise EndpointPolicyError("invalid URL") from exc
    if parsed.scheme not in ("http", "https"):
        raise EndpointPolicyError("only http(s) endpoints are allowed")
    if parsed.username or parsed.password:
        raise EndpointPolicyError("credentials in URLs are not allowed")
    if parsed.fragment:
        raise EndpointPolicyError("URL fragments are not allowed")
    host = (parsed.hostname or "").lower()
    if not host:
        raise EndpointPolicyError("URL has no hostname")

    trusted = CREDENTIAL_TRUSTED_HOSTS.get(credential_env or "") if credential_env else None
    allowlist = [h.lower() for h in allowed_hosts]
    if not ((trusted is not None and host == trusted) or host in allowlist):
        raise EndpointPolicyError(
            f"endpoint host '{host}' is not a trusted provider endpoint and is not in "
            "the administrator allowlist")
    return host


def validate_endpoint_url(url: str, *, allow_local: bool, allowed_hosts: list[str],
                          credential_env: str | None = None) -> str:
    """Validate + resolve + IP-check (DNS used; prefer pinned_client for the
    connect-time guarantee)."""
    host = validate_endpoint_policy(url, allowed_hosts=allowed_hosts,
                                    credential_env=credential_env)
    try:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EndpointPolicyError(f"endpoint host '{host}' cannot be resolved") from exc
    except ValueError as exc:
        raise EndpointPolicyError("invalid URL") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _ip_is_forbidden(ip, allow_local):
            raise EndpointPolicyError(
                "endpoint resolves to a forbidden address (private/loopback/metadata)")
    return host


def safe_request(client_factory, method: str, url: str, *, max_redirects: int = 3,
                 allow_local: bool, allowed_hosts: list[str],
                 credential_env: str | None = None, max_bytes: int = 2_000_000,
                 **kwargs) -> httpx.Response:
    """Perform an outbound request with hop-by-hop endpoint validation (each
    redirect re-checks scheme, allowlist, and resolved IPs for the SAME
    credential) and a response-size cap. Never follows redirects automatically."""
    hop_url = url
    for hop in range(max_redirects + 1):
        validate_endpoint_url(hop_url, allow_local=allow_local, allowed_hosts=allowed_hosts,
                              credential_env=credential_env)
        with client_factory(hop_url) as client:
            client.follow_redirects = False
            resp = client.request(method, hop_url, **kwargs)
        if resp.is_redirect and hop < max_redirects:
            loc = resp.headers.get("location", "")
            if not loc:
                return resp
            from urllib.parse import urljoin
            hop_url = urljoin(hop_url, loc)
            continue
        # cap response size defensively
        if len(resp.content) > max_bytes:
            raise EndpointPolicyError("provider response exceeds size limit")
        return resp
    raise EndpointPolicyError("too many redirects")
