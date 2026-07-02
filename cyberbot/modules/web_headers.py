"""Analyse des en-têtes de sécurité HTTP et des cookies.

⚠️ Actif : effectue une requête HTTP(S) vers la cible (périmètre requis).
"""

from __future__ import annotations

from ..core.findings import Finding, Severity
from ..utils.net import http_request, parse_host

NAME = "headers"

# En-tête -> (sévérité si absent, recommandation, référence).
SECURITY_HEADERS = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "Activer HSTS : max-age>=31536000; includeSubDomains.",
        "https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Définir une CSP restrictive pour limiter XSS/injections.",
        "https://owasp.org/www-project-secure-headers/#content-security-policy",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Ajouter 'X-Content-Type-Options: nosniff'.",
        "https://owasp.org/www-project-secure-headers/#x-content-type-options",
    ),
    "x-frame-options": (
        Severity.LOW,
        "Ajouter 'X-Frame-Options: DENY' ou une directive frame-ancestors en CSP.",
        "https://owasp.org/www-project-secure-headers/#x-frame-options",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Définir 'Referrer-Policy: no-referrer' ou 'strict-origin-when-cross-origin'.",
        "https://owasp.org/www-project-secure-headers/#referrer-policy",
    ),
    "permissions-policy": (
        Severity.INFO,
        "Définir une Permissions-Policy pour restreindre les API navigateur.",
        "https://owasp.org/www-project-secure-headers/#permissions-policy",
    ),
}

# En-têtes divulguant des informations.
LEAKY_HEADERS = {
    "server": "Masquer/minimiser l'en-tête Server pour ne pas divulguer la version.",
    "x-powered-by": "Supprimer 'X-Powered-By' (divulgation de technologie).",
    "x-aspnet-version": "Supprimer 'X-AspNet-Version'.",
    "x-aspnetmvc-version": "Supprimer 'X-AspNetMvc-Version'.",
}


def _normalize_url(target: str) -> str:
    host, port, scheme = parse_host(target)
    if scheme:
        return target
    # Par défaut HTTPS.
    if port:
        return f"https://{host}:{port}"
    return f"https://{host}"


def run(target: str, ctx) -> list[Finding]:
    log = ctx.logger
    url = _normalize_url(target)
    findings: list[Finding] = []

    log.info(f"Requête HTTP vers {url}")
    try:
        resp = http_request(url, timeout=ctx.options.get("http_timeout", 8.0))
    except Exception as e:  # noqa: BLE001
        # Repli en HTTP si HTTPS échoue.
        if url.startswith("https://"):
            fallback = "http://" + url[len("https://"):]
            log.warn(f"HTTPS échoué ({e}); tentative en {fallback}")
            try:
                resp = http_request(fallback, timeout=ctx.options.get("http_timeout", 8.0))
                url = fallback
                findings.append(
                    Finding(
                        title="HTTPS indisponible, service accessible en HTTP",
                        severity=Severity.MEDIUM,
                        target=url,
                        module=NAME,
                        description="Le service répond en HTTP clair mais pas en HTTPS.",
                        recommendation="Activer TLS et rediriger tout le trafic vers HTTPS.",
                    )
                )
            except Exception as e2:  # noqa: BLE001
                log.error(f"Requête impossible : {e2}")
                return findings
        else:
            log.error(f"Requête impossible : {e}")
            return findings

    log.good(f"Réponse HTTP {resp.status} ({len(resp.body)} octets)")
    headers = resp.headers

    # En-têtes de sécurité manquants.
    for h, (sev, reco, ref) in SECURITY_HEADERS.items():
        if h not in headers:
            findings.append(
                Finding(
                    title=f"En-tête de sécurité manquant : {h}",
                    severity=sev,
                    target=url,
                    module=NAME,
                    description=f"La réponse ne contient pas l'en-tête '{h}'.",
                    recommendation=reco,
                    references=[ref],
                )
            )
            log.warn(f"En-tête manquant : {h}")

    # En-têtes divulguant des infos.
    for h, reco in LEAKY_HEADERS.items():
        if h in headers:
            findings.append(
                Finding(
                    title=f"Divulgation d'information via l'en-tête : {h}",
                    severity=Severity.LOW,
                    target=url,
                    module=NAME,
                    description=f"L'en-tête '{h}' expose : {headers[h]}",
                    evidence=f"{h}: {headers[h]}",
                    recommendation=reco,
                )
            )

    # Analyse des cookies.
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        lc = set_cookie.lower()
        if "secure" not in lc:
            findings.append(
                Finding(
                    title="Cookie sans attribut Secure",
                    severity=Severity.MEDIUM,
                    target=url,
                    module=NAME,
                    description="Au moins un cookie n'a pas l'attribut 'Secure'.",
                    evidence=set_cookie[:300],
                    recommendation="Ajouter 'Secure' à tous les cookies de session.",
                )
            )
        if "httponly" not in lc:
            findings.append(
                Finding(
                    title="Cookie sans attribut HttpOnly",
                    severity=Severity.MEDIUM,
                    target=url,
                    module=NAME,
                    description="Au moins un cookie n'a pas l'attribut 'HttpOnly'.",
                    evidence=set_cookie[:300],
                    recommendation="Ajouter 'HttpOnly' pour empêcher l'accès JS aux cookies.",
                )
            )
        if "samesite" not in lc:
            findings.append(
                Finding(
                    title="Cookie sans attribut SameSite",
                    severity=Severity.LOW,
                    target=url,
                    module=NAME,
                    description="Au moins un cookie n'a pas d'attribut 'SameSite'.",
                    evidence=set_cookie[:300],
                    recommendation="Définir 'SameSite=Lax' ou 'Strict' contre le CSRF.",
                )
            )

    if not findings:
        log.good("En-têtes de sécurité conformes aux bonnes pratiques principales.")
    return findings
