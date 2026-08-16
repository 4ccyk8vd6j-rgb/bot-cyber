"""Aides réseau basées sur la bibliothèque standard (pas de dépendance)."""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .sanitize import clean_line

USER_AGENT = "CyberBot/1.0 (+authorized-security-scan)"
DEFAULT_TIMEOUT = 8.0

# Seuls schémas autorisés pour une requête sortante. Sans cette restriction,
# urllib traite 'file:///etc/passwd' et le contenu atterrit dans un rapport.
ALLOWED_SCHEMES = {"http", "https"}

# Nombre maximal de redirections suivies manuellement.
MAX_REDIRECTS = 5


class UnsafeRequestError(Exception):
    """Requête refusée : schéma interdit ou redirection hors périmètre."""


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Neutralise le suivi automatique : les redirections sont gérées à la main."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def _assert_scheme_allowed(url: str) -> None:
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeRequestError(
            f"Schéma d'URL refusé : '{scheme or '(vide)'}'. "
            f"Schémas autorisés : {', '.join(sorted(ALLOWED_SCHEMES))}."
        )


def _single_request(
    url: str,
    method: str,
    hdrs: dict[str, str],
    data: bytes | None,
    timeout: float,
    max_body: int,
) -> HttpResponse:
    opener = urllib.request.build_opener(_NoRedirect())
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


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
    max_body: int = 2_000_000,
    is_allowed: Callable[[str], bool] | None = None,
) -> HttpResponse:
    """Requête HTTP(S) minimale via urllib.

    - Vérifie toujours les certificats TLS (contexte par défaut).
    - Refuse tout schéma autre que http/https.
    - Suit les redirections **manuellement** : `is_allowed` est réévalué sur
      l'hôte de chaque saut. Sans ce contrôle, une cible autorisée pourrait
      rediriger l'analyse vers un hôte interdit (métadonnées cloud, réseau
      interne), contournant le périmètre.
    """
    _assert_scheme_allowed(url)

    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)

    current = url
    for _ in range(MAX_REDIRECTS + 1):
        resp = _single_request(current, method, hdrs, data, timeout, max_body)

        if not allow_redirects or resp.status not in (301, 302, 303, 307, 308):
            return resp

        location = resp.headers.get("location")
        if not location:
            return resp

        target = urllib.parse.urljoin(current, location.strip())
        _assert_scheme_allowed(target)

        if is_allowed is not None:
            host = urllib.parse.urlparse(target).hostname or ""
            if not is_allowed(host):
                raise UnsafeRequestError(
                    f"Redirection hors périmètre refusée : {current} → {target}. "
                    "La cible tente de faire analyser un hôte non autorisé."
                )

        # 303, et 301/302 sur POST, imposent un GET sans corps (RFC 9110).
        if resp.status == 303 or (resp.status in (301, 302) and method == "POST"):
            method, data = "GET", None

        current = target

    raise UnsafeRequestError(f"Trop de redirections (> {MAX_REDIRECTS}) depuis {url}.")


def resolve_base_url(
    target: str,
    timeout: float = DEFAULT_TIMEOUT,
    is_allowed: Callable[[str], bool] | None = None,
) -> str:
    """Détermine l'URL de base utilisable pour une cible.

    Si la cible précise déjà un schéma, il est conservé. Sinon HTTPS est
    tenté en premier, puis HTTP en repli : sans cela, un service en clair
    sur un port non standard serait déclaré injoignable à tort.
    """
    host, port, scheme = parse_host(target)
    if scheme:
        _assert_scheme_allowed(target)
        return target.rstrip("/")

    authority = f"{host}:{port}" if port else host
    candidates = [f"https://{authority}", f"http://{authority}"]

    for candidate in candidates:
        try:
            http_request(
                candidate,
                timeout=timeout,
                allow_redirects=False,
                max_body=1,
                is_allowed=is_allowed,
            )
            return candidate
        except UnsafeRequestError:
            raise
        except Exception:  # noqa: BLE001
            continue

    # Aucun des deux n'a répondu : on renvoie HTTPS pour que l'appelant
    # remonte une erreur explicite.
    return candidates[0]


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    """Retourne True si le port TCP accepte une connexion."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Tente une lecture de bannière après connexion (best effort).

    La bannière est contrôlée par la cible : elle est assainie avant d'être
    renvoyée, car elle est affichée dans le terminal de l'analyste.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
                return clean_line(data.decode("latin-1", errors="replace"), max_length=200)
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
