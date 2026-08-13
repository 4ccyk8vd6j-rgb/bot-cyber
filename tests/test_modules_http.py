"""Tests des modules actifs contre un serveur HTTP local jetable."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberbot.core.findings import Severity
from cyberbot.modules import cors_check, exposure, web_headers
from cyberbot.utils.logging import Logger


class _Ctx:
    def __init__(self, opts=None):
        self.logger = Logger(verbose=False, use_color=False)
        self.options = opts or {}
        self.scope = None


def _make_handler(routes, reflect_origin):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = routes.get(self.path)
            origin = self.headers.get("Origin")
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            if reflect_origin and origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


def _serve(routes, reflect_origin=False):
    server = HTTPServer(("127.0.0.1", 0), _make_handler(routes, reflect_origin))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture
def plain_server():
    server, url = _serve({"/": b"hello"})
    yield url
    server.shutdown()


def test_headers_module_flags_missing_security_headers(plain_server):
    findings = web_headers.run(plain_server, _Ctx())
    titles = " ".join(f.title for f in findings)
    assert "content-security-policy" in titles
    assert "strict-transport-security" in titles


def test_cors_reflected_origin_is_critical_with_credentials():
    server, url = _serve({"/": b"{}"}, reflect_origin=True)
    try:
        findings = cors_check.run(url, _Ctx())
    finally:
        server.shutdown()
    reflected = [f for f in findings if "origine arbitraire" in f.title.lower()]
    assert reflected, "l'origine reflétée doit être détectée"
    assert reflected[0].severity is Severity.CRITICAL


def test_cors_clean_server_reports_no_permissive_policy(plain_server):
    findings = cors_check.run(plain_server, _Ctx())
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFO


def test_exposure_detects_env_and_redacts_secret():
    routes = {
        "/.env": b"DB_PASSWORD=hunter2\nAPI_KEY=topsecret\n",
        "/robots.txt": b"User-agent: *\n",
    }
    server, url = _serve(routes)
    try:
        findings = exposure.run(url, _Ctx({"exposure_delay": 0}))
    finally:
        server.shutdown()

    env = [f for f in findings if f.target.endswith("/.env")]
    assert env, ".env exposé doit être détecté"
    assert env[0].severity is Severity.CRITICAL
    # La preuve ne doit jamais contenir le secret en clair.
    assert "hunter2" not in env[0].evidence
    assert "topsecret" not in env[0].evidence
    assert "«masqué»" in env[0].evidence


def test_exposure_soft404_is_inconclusive():
    """Un serveur qui répond 200 à tout doit produire un résultat non concluant."""

    class AlwaysOk(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), AlwaysOk)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        findings = exposure.run(url, _Ctx({"exposure_delay": 0}))
    finally:
        server.shutdown()

    assert len(findings) == 1
    assert "non concluant" in findings[0].title.lower()
