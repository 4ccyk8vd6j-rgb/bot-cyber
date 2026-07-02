"""Contrôle de la configuration TLS/SSL (certificat + protocole).

⚠️ Actif : établit une connexion TLS vers la cible (périmètre requis).
"""

from __future__ import annotations

import datetime as _dt
import ssl

from ..core.findings import Finding, Severity
from ..utils.net import get_tls_certificate, parse_host

NAME = "tls"

# Protocoles obsolètes -> sévérité.
WEAK_PROTOCOLS = {
    "SSLv2": Severity.CRITICAL,
    "SSLv3": Severity.CRITICAL,
    "TLSv1": Severity.HIGH,
    "TLSv1.0": Severity.HIGH,
    "TLSv1.1": Severity.MEDIUM,
}


def _parse_cert_date(value: str) -> _dt.datetime:
    # Format OpenSSL : 'Jun  1 12:00:00 2025 GMT'
    return _dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=_dt.timezone.utc
    )


def run(target: str, ctx) -> list[Finding]:
    log = ctx.logger
    host, port, _ = parse_host(target)
    host = host or target
    port = port or 443
    findings: list[Finding] = []

    log.info(f"Connexion TLS à {host}:{port}")
    try:
        info = get_tls_certificate(host, port, timeout=ctx.options.get("tls_timeout", 6.0))
    except ssl.SSLCertVerificationError as e:
        findings.append(
            Finding(
                title="Échec de vérification du certificat TLS",
                severity=Severity.HIGH,
                target=f"{host}:{port}",
                module=NAME,
                description="Le certificat n'a pas pu être vérifié (chaîne/nom invalide).",
                evidence=str(e),
                recommendation="Installer un certificat valide émis par une CA de confiance.",
            )
        )
        log.error(f"Certificat invalide : {e}")
        return findings
    except Exception as e:  # noqa: BLE001
        log.error(f"Connexion TLS impossible : {e}")
        return findings

    protocol = info["protocol"]
    cipher = info["cipher"]
    cert = info["cert"] or {}
    log.good(f"TLS négocié : {protocol} · {cipher[0] if cipher else '?'}")

    # Protocole faible.
    if protocol in WEAK_PROTOCOLS:
        findings.append(
            Finding(
                title=f"Protocole TLS obsolète négocié : {protocol}",
                severity=WEAK_PROTOCOLS[protocol],
                target=f"{host}:{port}",
                module=NAME,
                description=f"Le serveur a négocié {protocol}.",
                recommendation="Désactiver SSLv2/3 et TLS 1.0/1.1 ; n'autoriser que TLS 1.2+.",
                references=["https://datatracker.ietf.org/doc/html/rfc8996"],
            )
        )

    # Expiration du certificat.
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = _parse_cert_date(not_after)
            days = (exp - _dt.datetime.now(_dt.timezone.utc)).days
            if days < 0:
                sev = Severity.CRITICAL
                desc = f"Le certificat a expiré depuis {abs(days)} jour(s)."
            elif days < 15:
                sev = Severity.HIGH
                desc = f"Le certificat expire dans {days} jour(s)."
            elif days < 30:
                sev = Severity.MEDIUM
                desc = f"Le certificat expire dans {days} jour(s)."
            else:
                sev = Severity.INFO
                desc = f"Certificat valide encore {days} jour(s)."
            findings.append(
                Finding(
                    title="Validité du certificat TLS",
                    severity=sev,
                    target=f"{host}:{port}",
                    module=NAME,
                    description=desc,
                    evidence=f"notAfter = {not_after}",
                    recommendation=(
                        "Renouveler le certificat et automatiser le renouvellement (ex. ACME)."
                        if sev.rank >= Severity.MEDIUM.rank
                        else ""
                    ),
                )
            )
            if sev.rank >= Severity.MEDIUM.rank:
                log.warn(desc)
        except ValueError:
            pass

    # Émetteur / sujet (info).
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    findings.append(
        Finding(
            title="Informations du certificat",
            severity=Severity.INFO,
            target=f"{host}:{port}",
            module=NAME,
            description="Détails du certificat présenté par le serveur.",
            evidence=(
                f"Sujet : {subject.get('commonName', '?')}\n"
                f"Émetteur : {issuer.get('organizationName', issuer.get('commonName', '?'))}\n"
                f"Protocole : {protocol}\n"
                f"Cipher : {cipher[0] if cipher else '?'}"
            ),
        )
    )

    return findings
