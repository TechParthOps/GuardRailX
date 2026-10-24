"""Request-body limit tests (Phase 8): declared, streamed, malformed, near-limit."""
import json

from tests.conftest import researcher_headers  # noqa: F401


def test_oversized_declared_body_rejected(client, researcher_headers):
    big = b'{"name":"' + b"x" * (2 * 1024 * 1024) + b'"}'
    r = client.post("/api/v1/projects", headers={**researcher_headers,
                    "Content-Type": "application/json", "Content-Length": str(len(big))},
                    content=big)
    assert r.status_code == 413
    assert r.headers.get("X-Content-Type-Options") == "nosniff"  # security headers on 413


def test_streamed_oversized_body_rejected(client, researcher_headers):
    """Chunked body with NO reliable Content-Length is still bounded (Phase 8)."""
    payload = b'{"name":"' + b"x" * (2 * 1024 * 1024) + b'"}'

    def stream():
        for i in range(0, len(payload), 65536):
            yield payload[i:i + 65536]

    r = client.post("/api/v1/projects", headers={**researcher_headers,
                    "Content-Type": "application/json"}, content=stream())
    assert r.status_code == 413


def test_malformed_content_length_ignored_for_small_bodies(client, researcher_headers):
    """Garbage Content-Length with a small body must not break the request."""
    r = client.post("/api/v1/projects", headers={**researcher_headers,
                    "Content-Type": "application/json", "Content-Length": "abc"},
                    content=json.dumps({"name": "malformed-cl-proj"}).encode())
    assert r.status_code in (200, 422)  # processed normally (validation decides)


def test_legitimate_body_near_limit_succeeds(client, researcher_headers):
    """A request just under the cap is processed (wire size ~700KB via JSON
    whitespace padding, which json.loads accepts)."""
    payload = json.dumps({"name": f"near-limit-{researcher_headers['Authorization'][-6:]}",
                          "description": "legitimate"}).encode()
    body = payload + b" " * 700_000
    r = client.post("/api/v1/projects", headers={**researcher_headers,
                    "Content-Type": "application/json"}, content=body)
    assert r.status_code == 200, r.text
    projects = client.get("/api/v1/projects", headers=researcher_headers).json()
    assert any(p["name"].startswith("near-limit-") for p in projects)


def test_get_requests_not_affected(client, researcher_headers):
    assert client.get("/api/v1/projects", headers=researcher_headers).status_code == 200
