"""Détection de fichiers/chemins sensibles exposés publiquement.

⚠️ Actif : requêtes HTTP sur une liste COURTE et ciblée de chemins connus
(périmètre requis). Ce n'est volontairement pas un fuzzer : la liste est
curatée, les requêtes sont espacées, et aucun contenu n'est exfiltré —
seule la taille et un extrait tronqué servent de preuve.

Objectif : vérifier que vos propres déploiements n'exposent pas de fichiers
de configuration, de sauvegardes ou de métadonnées de dépôt.
"""

from __future__ import annotations

import re
import time

from ..core.findings import Finding, Severity
from ..utils.net import http_request, parse_host

NAME = "exposure"

# Chemins dont le contenu est lui-même un secret : la preuve doit être masquée
# pour ne pas recopier des identifiants en clair dans les rapports.
REDACT_PATHS = {"/.env", "/.htpasswd", "/backup.sql", "/config.php.bak"}


def _redact_evidence(text: str) -> str:
    """Masque la partie droite des affectations (CLE=valeur, user:hash)."""
    out = []
    for line in text.splitlines()[:6]:
        line = re.sub(r"(=\s*)(\S+)", lambda m: m.group(1) + "«masqué»", line)
        line = re.sub(r"(:)([^\s:]{3,})", lambda m: m.group(1) + "«masqué»", line)
        out.append(line)
    return "\n".join(out)

# chemin -> (libellé, sévérité, signature attendue dans le corps)
SENSITIVE_PATHS: dict[str, tuple[str, Severity, str]] = {
    "/.git/config": ("Dépôt Git exposé", Severity.HIGH, "[core]"),
    "/.env": ("Fichier d'environnement exposé", Severity.CRITICAL, "="),
    "/.svn/entries": ("Métadonnées SVN exposées", Severity.MEDIUM, ""),
    "/.DS_Store": ("Fichier .DS_Store exposé", Severity.LOW, ""),
    "/config.php.bak": ("Sauvegarde de configuration exposée", Severity.HIGH, ""),
    "/backup.sql": ("Dump de base de données exposé", Severity.CRITICAL, ""),
    "/.htpasswd": ("Fichier .htpasswd exposé", Severity.CRITICAL, ":"),
    "/server-status": ("Apache server-status exposé", Severity.MEDIUM, "Apache"),
    "/phpinfo.php": ("phpinfo() exposé", Severity.MEDIUM, "phpinfo"),
    "/.well-known/security.txt": ("security.txt présent", Severity.INFO, ""),
    "/robots.txt": ("robots.txt présent", Severity.INFO, ""),
}

# Ces chemins sont informatifs : leur présence est une bonne pratique.
BENIGN = {"/.well-known/security.txt", "/robots.txt"}


def _normalize_base(target: str) -> str:
    host, port, scheme = parse_host(target)
    if scheme:
        return target.rstrip("/")
    return (f"https://{host}:{port}" if port else f"https://{host}").rstrip("/")


def run(target: str, ctx) -> list[Finding]:
    log = ctx.logger
    base = _normalize_base(target)
    timeout = ctx.options.get("http_timeout", 8.0)
    delay = ctx.options.get("exposure_delay", 0.3)
    findings: list[Finding] = []

    log.info(f"Vérification de {len(SENSITIVE_PATHS)} chemins sensibles sur {base}")

    # Détecte les serveurs qui répondent 200 à tout (soft-404).
    control = None
    try:
        control = http_request(
            f"{base}/cyberbot-chemin-inexistant-9f3a2b", timeout=timeout, allow_redirects=False
        )
    except Exception as e:  # noqa: BLE001
        log.error(f"Cible injoignable : {e}")
        return findings

    if control.status == 200:
        log.warn("Le serveur répond 200 sur un chemin inexistant : résultats non fiables.")
        return [
            Finding(
                title="Contrôle d'exposition non concluant (soft-404)",
                severity=Severity.INFO,
                target=base,
                module=NAME,
                description=(
                    "Le serveur renvoie 200 pour un chemin manifestement inexistant ; "
                    "impossible de distinguer un fichier réellement exposé."
                ),
                recommendation="Renvoyer un vrai code 404 pour les ressources absentes.",
            )
        ]

    for path, (label, sev, signature) in SENSITIVE_PATHS.items():
        time.sleep(delay)
        try:
            resp = http_request(f"{base}{path}", timeout=timeout, allow_redirects=False)
        except Exception as e:  # noqa: BLE001
            log.debug(f"{path} : {e}")
            continue

        if resp.status != 200 or not resp.body:
            continue
        if signature and signature not in resp.text[:4000]:
            log.debug(f"{path} : 200 mais signature absente, ignoré.")
            continue

        if path in BENIGN:
            log.good(f"{path} présent ({len(resp.body)} octets)")
        else:
            log.warn(f"{label} → {base}{path}")

        snippet = resp.text[:200].strip()
        if path in REDACT_PATHS:
            snippet = _redact_evidence(snippet)

        findings.append(
            Finding(
                title=label,
                severity=sev,
                target=f"{base}{path}",
                module=NAME,
                description=(
                    f"Le chemin {path} est accessible publiquement (HTTP 200, "
                    f"{len(resp.body)} octets)."
                ),
                evidence=snippet,
                recommendation=(
                    ""
                    if path in BENIGN
                    else "Bloquer l'accès à ce chemin et retirer le fichier du serveur web."
                ),
            )
        )

    if not any(f.severity.rank > Severity.INFO.rank for f in findings):
        log.good("Aucun fichier sensible exposé détecté.")

    return findings
