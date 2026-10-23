"""Dashboard static assets must be served and the SPA must parse.

Guards against the 'stuck at Loading...' failure mode: a syntax error in
static/app.js silently disables the whole UI while the server stays healthy.
"""
import shutil
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

STATIC = Path(__file__).resolve().parent.parent / "static"


def test_index_references_assets_and_footer(client: TestClient):
    r = client.get("/")
    assert r.status_code == 200
    html = r.text
    assert "/static/app.js" in html and "/static/styles.css" in html
    assert "GUARDRAIL-X" in html


def test_app_js_is_served_with_js_content_type(client: TestClient):
    r = client.get("/static/app.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "")


def test_app_js_parses():
    """Syntax-check the dashboard bundle (node if available, else basic braces)."""
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    node = shutil.which("node")
    if node:
        proc = subprocess.run([node, "--check", str(STATIC / "app.js")],
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, f"app.js syntax error:\n{proc.stderr}"
    else:  # fallback: balanced braces/parens outside strings is a weak but useful signal
        for open_c, close_c in (("{", "}"), ("(", ")"), ("[", "]")):
            assert js.count(open_c) == js.count(close_c), f"unbalanced {open_c}{close_c}"
        assert "function esc" in js and "async function route" in js


def test_styles_css_served(client: TestClient):
    r = client.get("/static/styles.css")
    assert r.status_code == 200
    assert "--accent" in r.text  # theme variables present
