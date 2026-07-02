"""Aides réseau basées sur la bibliothèque standard (pas de dépendance)."""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

USER_AGENT = "CyberBot/1.0 (+authorized-security-scan)"
DEFAULT_TIMEOUT = 8.0


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
    max_body: int = 2_000_000,
) -> HttpResponse:
    """Requête HTTP(S) minimale via urllib.

    Vérifie toujours les certificats TLS (contexte par défaut).
    """
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: D401
            return None

    handlers = [] if allow_redirects else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_body)
            return HttpResponse(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=body,
                url=resp.geturl(),
            )
    except urllib.error.HTTPError as e:
        body = e.read(max_body) if hasattr(e, "read") else b""
        return HttpResponse(
            status=e.code,
            headers={k.lower(): v for k, v in (e.headers or {}).items()},
            body=body,
            url=url,
        )


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    """Retourne True si le port TCP accepte une connexion."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Tente une lecture de bannière après connexion (best effort)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
                return data.decode("latin-1", errors="replace").strip()
            except socket.timeout:
                return ""
    except OSError:
        return ""


def get_tls_certificate(host: str, port: int = 443, timeout: float = 6.0) -> dict[str, Any]:
    """Récupère le certificat et la version TLS négociée."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return {
                "cert": ssock.getpeercert(),
                "protocol": ssock.version(),
                "cipher": ssock.cipher(),
            }


def parse_host(target: str) -> tuple[str, int | None, str]:
    """Décompose une URL ou un host en (host, port, scheme)."""
    if "://" in target:
        u = urllib.parse.urlparse(target)
        host = u.hostname or ""
        port = u.port
        scheme = u.scheme
        return host, port, scheme
    if target.count(":") == 1 and not target.startswith("["):
        host, _, port_s = target.partition(":")
        try:
            return host, int(port_s), ""
        except ValueError:
            return target, None, ""
    return target, None, ""
