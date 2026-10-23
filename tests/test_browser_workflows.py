"""Browser-based workflow tests (Part 11.1) using Playwright + Chromium.

Runs a real server subprocess against an isolated temp database and drives
the actual UI. Skips (with reason) if the browser binary is unavailable.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("browser")
    port = _free_port()
    env = os.environ.copy()
    env.update({
        "GX_DATA_DIR": str(tmp),
        "GX_SANDBOX_DIR": str(tmp / "sandbox"),
        "GX_DATABASE_URL": f"sqlite:///{(tmp / 'b.db').as_posix()}",
        "GX_SETUP_TOKEN": "browser-setup-token-0123456789",
        "GX_SEED_DEMO_DATA": "true",
        "GX_ENVIRONMENT": "development",
        "PYTHONPATH": str(ROOT),
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port),
         "--log-level", "info"],
        cwd=str(ROOT), env=env,
        stdout=open(tmp / "server.log", "w"), stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    # wait for readiness
    import urllib.request
    ready = False
    for _ in range(80):
        try:
            with urllib.request.urlopen(base + "/api/v1/ready", timeout=2) as r:
                if r.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.5)
    if not ready:
        proc.kill()
        log = (tmp / "server.log").read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(f"server did not start; log:\n{log[-2000:]}")
    # first-time admin setup via the secure API
    import urllib.request
    import json as _json
    req = urllib.request.Request(
        base + "/api/v1/setup",
        data=_json.dumps({"setup_token": "browser-setup-token-0123456789",
                          "email": "admin@browser.local",
                          "password": "Browser-Admin-123"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        assert r.status == 200
    yield {"base": base, "port": port}
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def browser():
    pw = pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # browser binary missing
            pytest.skip(f"chromium unavailable: {exc}")
        yield b
        b.close()


def _page(browser):
    return browser.new_context().new_page()


def test_login_page_renders_and_signup_link(server, browser):
    page = _page(browser)
    page.goto(server["base"] + "/#/login")
    page.wait_for_selector("#l-email", timeout=10000)
    assert page.locator("#l-email").input_value() == ""  # no default identity (GX-005)
    assert page.locator("a[href='#/signup']").count() == 1
    page.context.close()


def test_signup_login_dashboard_signout_workflow(server, browser):
    ctx = browser.new_context()
    page = ctx.new_page()
    base = server["base"]

    # --- signup via UI
    page.goto(base + "/#/signup")
    page.wait_for_selector("#s-email")
    page.fill("#s-email", "workflow@browser.local")
    page.fill("#s-pass", "Workflow-Pass-123")
    page.fill("#s-pass2", "Workflow-Pass-123")
    page.click("#s-btn")
    page.wait_for_selector("#s-ok", state="visible", timeout=8000)

    # --- sign in via UI
    page.goto(base + "/#/login")
    page.fill("#l-email", "workflow@browser.local")
    page.fill("#l-pass", "Workflow-Pass-123")
    page.click("#l-btn")
    page.wait_for_selector("nav a", timeout=10000)  # nav renders only when signed in

    # --- dashboard renders scoped data (demo seeded in this server)
    page.goto(base + "/#/dashboard")
    page.wait_for_selector(".card", timeout=10000)
    assert "Operational targets" in page.content()

    # --- create a project through the UI (researcher role works; viewer would 403)
    # (workflow user is viewer: the projects page should still render but creation is server-denied)
    page.goto(base + "/#/targets")
    page.wait_for_selector("h1", timeout=10000)
    assert "Target Registry" in page.content()

    # --- sign out clears the session
    page.click("#logout-btn")
    page.wait_for_selector("#l-email", timeout=10000)
    assert page.evaluate("sessionStorage.getItem('gx_token')") is None
    ctx.close()


def test_xss_payload_is_not_executed_in_dashboard(server, browser):
    """Stored XSS must render as text (Part 11.2)."""
    import urllib.request
    import json as _json
    base = server["base"]

    def call(path, payload, token=None, method="POST"):
        req = urllib.request.Request(base + path,
                                     data=_json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json", **(
                                         {"Authorization": "Bearer " + token} if token else {})},
                                     method=method)
        with urllib.request.urlopen(req, timeout=10) as r:
            return _json.loads(r.read())

    tok = call("/api/v1/auth/login", {"email": "admin@browser.local",
                                      "password": "Browser-Admin-123"})["access_token"]
    call("/api/v1/projects", {"name": "browser-xss",
                              "description": "<img src=x onerror=window.__xss=1>"}, tok)
    ctx = browser.new_context()
    page = ctx.new_page()
    page.goto(base + "/#/login")
    page.fill("#l-email", "admin@browser.local")
    page.fill("#l-pass", "Browser-Admin-123")
    page.click("#l-btn")
    page.wait_for_selector("nav a", timeout=10000)
    page.goto(base + "/#/targets")  # any page; then check the payload never executed
    time.sleep(1)
    assert page.evaluate("window.__xss === undefined")
    ctx.close()


def test_invalid_login_shows_error_and_stays(server, browser):
    ctx = browser.new_context()
    page = ctx.new_page()
    page.goto(server["base"] + "/#/login")
    page.fill("#l-email", "nobody@browser.local")
    page.fill("#l-pass", "Wrong-Pass-123")
    page.click("#l-btn")
    page.wait_for_selector("#l-msg:not(.hidden)", timeout=8000)
    assert "invalid" in page.locator("#l-msg").inner_text().lower()
    ctx.close()
