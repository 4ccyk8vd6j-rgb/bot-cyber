"""Détection de mauvaises configurations CORS.

⚠️ Actif : envoie quelques requêtes HTTP avec des en-têtes Origin variés
(périmètre requis). Aucune exploitation n'est effectuée : le module se
contente d'observer les en-têtes de réponse.
"""

from __future__ import annotations

from ..core.findings import Finding, Severity
from ..utils.net import http_request, parse_host

NAME = "cors"

EVIL_ORIGIN = "https://cyberbot-cors-test.example"


def _normalize_url(target: str) -> str:
    host, port, scheme = parse_host(target)
    if scheme:
        return target
    return f"https://{host}:{port}" if port else f"https://{host}"


def _probe(url: str, origin: str, timeout: float) -> dict[str, str]:
    resp = http_request(url, headers={"Origin": origin}, timeout=timeout)
    return resp.headers


def run(target: str, ctx) -> list[Finding]:
    log = ctx.logger
    url = _normalize_url(target)
    timeout = ctx.options.get("http_timeout", 8.0)
    findings: list[Finding] = []

    host, _, _ = parse_host(url)

    log.info(f"Test de la configuration CORS sur {url}")

    # 1) Origine arbitraire : est-elle renvoyée telle quelle ?
    try:
        headers = _probe(url, EVIL_ORIGIN, timeout)
    except Exception as e:  # noqa: BLE001
        log.error(f"Requête CORS impossible : {e}")
        return findings

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if not acao:
        log.good("Aucun en-tête CORS renvoyé pour une origine arbitraire.")
        findings.append(
            Finding(
                title="Aucune politique CORS permissive détectée",
                severity=Severity.INFO,
                target=url,
                module=NAME,
                description="Le serveur ne renvoie pas d'Access-Control-Allow-Origin pour une origine inconnue.",
            )
        )
        return findings

    if acao == EVIL_ORIGIN:
        sev = Severity.CRITICAL if acac == "true" else Severity.HIGH
        desc = (
            "Le serveur reflète n'importe quelle origine dans "
            "Access-Control-Allow-Origin."
        )
        if acac == "true":
            desc += (
                " Combiné à Access-Control-Allow-Credentials: true, un site "
                "malveillant peut lire les réponses authentifiées de la victime."
            )
        log.warn("Origine arbitraire reflétée dans Access-Control-Allow-Origin !")
        findings.append(
            Finding(
                title="CORS : origine arbitraire reflétée",
                severity=sev,
                target=url,
                module=NAME,
                description=desc,
                evidence=(
                    f"Origin envoyé : {EVIL_ORIGIN}\n"
                    f"access-control-allow-origin: {acao}\n"
                    f"access-control-allow-credentials: {acac or '(absent)'}"
                ),
                recommendation=(
                    "Valider l'origine contre une liste blanche stricte ; ne jamais "
                    "refléter l'en-tête Origin reçu."
                ),
                references=["https://portswigger.net/web-security/cors"],
            )
        )
    elif acao == "*":
        sev = Severity.HIGH if acac == "true" else Severity.LOW
        findings.append(
            Finding(
                title="CORS : politique générique (*)",
                severity=sev,
                target=url,
                module=NAME,
                description=(
                    "Access-Control-Allow-Origin vaut '*'. Acceptable pour des données "
                    "publiques, dangereux si la ressource est authentifiée."
                ),
                evidence=(
                    f"access-control-allow-origin: *\n"
                    f"access-control-allow-credentials: {acac or '(absent)'}"
                ),
                recommendation="Restreindre l'origine si la ressource n'est pas publique.",
            )
        )

    # 2) Sous-domaine « null » : origine null souvent acceptée à tort.
    try:
        null_headers = _probe(url, "null", timeout)
        if null_headers.get("access-control-allow-origin", "").lower() == "null":
            sev = (
                Severity.HIGH
                if null_headers.get("access-control-allow-credentials", "").lower() == "true"
                else Severity.MEDIUM
            )
            log.warn("L'origine 'null' est acceptée.")
            findings.append(
                Finding(
                    title="CORS : origine 'null' autorisée",
                    severity=sev,
                    target=url,
                    module=NAME,
                    description=(
                        "L'origine 'null' est acceptée ; elle peut être forgée depuis "
                        "une iframe sandbox ou un document local."
                    ),
                    evidence="access-control-allow-origin: null",
                    recommendation="Ne jamais autoriser l'origine 'null'.",
                )
            )
    except Exception as e:  # noqa: BLE001
        log.debug(f"Sonde 'null' échouée : {e}")

    # 3) Préfixe/suffixe : origine du type evil-<domaine>.
    if host:
        for candidate in (f"https://evil{host}", f"https://{host}.cyberbot-test.example"):
            try:
                h = _probe(url, candidate, timeout)
            except Exception:  # noqa: BLE001
                continue
            if h.get("access-control-allow-origin", "") == candidate:
                log.warn(f"Validation d'origine trop laxiste : {candidate} accepté.")
                findings.append(
                    Finding(
                        title="CORS : validation d'origine par sous-chaîne",
                        severity=Severity.HIGH,
                        target=url,
                        module=NAME,
                        description=(
                            "Une origine contenant le domaine légitime en préfixe/suffixe "
                            "est acceptée : la validation repose sur une comparaison de "
                            "sous-chaîne contournable."
                        ),
                        evidence=f"Origin accepté : {candidate}",
                        recommendation="Comparer l'origine exactement, à partir d'une liste blanche.",
                    )
                )
                break

    return findings
