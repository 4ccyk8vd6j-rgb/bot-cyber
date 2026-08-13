"""Audit DNS : politiques anti-usurpation d'e-mail (SPF/DMARC), CAA, sous-domaines.

Passif : n'effectue que des requêtes DNS (aucune connexion à la cible).
Ces contrôles servent à vérifier que VOTRE domaine est correctement protégé
contre l'usurpation d'identité (spoofing) et l'émission de certificats.
"""

from __future__ import annotations

from ..core.findings import Finding, Severity
from ..utils.dns import DnsError, query, resolves
from ..utils.net import parse_host

NAME = "dns"

# Sous-domaines courants, testés par simple résolution (pas de brute force).
COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "imap", "ftp", "api", "dev", "staging",
    "test", "admin", "portal", "vpn", "remote", "git", "gitlab", "jenkins",
    "grafana", "kibana", "jira", "confluence", "db", "backup", "cdn", "static",
    "shop", "blog", "app", "beta", "demo", "intranet", "monitor", "status",
]


def _check_spf(domain: str, timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    try:
        records = query(domain, "TXT", timeout=timeout)
    except DnsError as e:
        return [
            Finding(
                title="Contrôle SPF non concluant",
                severity=Severity.INFO,
                target=domain,
                module=NAME,
                description="La requête TXT a échoué ; SPF n'a pas pu être vérifié.",
                evidence=str(e),
            )
        ]

    spf = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf:
        return [
            Finding(
                title="Enregistrement SPF absent",
                severity=Severity.MEDIUM,
                target=domain,
                module=NAME,
                description=(
                    "Aucun enregistrement SPF : n'importe qui peut tenter d'envoyer "
                    "des e-mails au nom de ce domaine."
                ),
                recommendation="Publier un TXT 'v=spf1 … -all' listant les émetteurs légitimes.",
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            )
        ]

    if len(spf) > 1:
        findings.append(
            Finding(
                title="Plusieurs enregistrements SPF publiés",
                severity=Severity.MEDIUM,
                target=domain,
                module=NAME,
                description="Plus d'un SPF rend la politique invalide (RFC 7208).",
                evidence="\n".join(spf),
                recommendation="Ne conserver qu'un seul enregistrement SPF.",
            )
        )

    record = spf[0]
    if record.rstrip().endswith("+all") or " +all" in record:
        sev = Severity.HIGH
        label = "politique permissive (+all)"
        desc = "La politique '+all' autorise n'importe quel serveur à émettre pour ce domaine."
    elif record.rstrip().endswith("~all"):
        sev = Severity.LOW
        label = "softfail (~all)"
        desc = "En 'softfail', les e-mails usurpés sont généralement acceptés puis simplement marqués."
    elif record.rstrip().endswith("-all"):
        sev = Severity.INFO
        label = "politique stricte (-all)"
        desc = "Politique stricte : configuration recommandée."
    else:
        sev = Severity.MEDIUM
        label = "mécanisme 'all' absent"
        desc = "Le SPF ne se termine pas par un mécanisme 'all' : le résultat est neutre par défaut."

    findings.append(
        Finding(
            title=f"SPF : {label}",
            severity=sev,
            target=domain,
            module=NAME,
            description=desc,
            evidence=record,
            recommendation=("Durcir la politique SPF en '-all'." if sev.rank >= Severity.LOW.rank else ""),
        )
    )
    return findings


def _check_dmarc(domain: str, timeout: float) -> list[Finding]:
    try:
        records = query(f"_dmarc.{domain}", "TXT", timeout=timeout)
    except DnsError as e:
        return [
            Finding(
                title="Contrôle DMARC non concluant",
                severity=Severity.INFO,
                target=domain,
                module=NAME,
                description="La requête TXT _dmarc a échoué.",
                evidence=str(e),
            )
        ]

    dmarc = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return [
            Finding(
                title="Enregistrement DMARC absent",
                severity=Severity.MEDIUM,
                target=domain,
                module=NAME,
                description=(
                    "Sans DMARC, aucune consigne n'est donnée aux serveurs destinataires "
                    "en cas d'échec SPF/DKIM."
                ),
                recommendation="Publier '_dmarc.<domaine> TXT v=DMARC1; p=quarantine; rua=mailto:…'.",
                references=["https://datatracker.ietf.org/doc/html/rfc7489"],
            )
        ]

    record = dmarc[0]
    policy = "none"
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            policy = part[2:].strip().lower()
            break

    sev = {
        "none": Severity.MEDIUM,
        "quarantine": Severity.LOW,
        "reject": Severity.INFO,
    }.get(policy, Severity.MEDIUM)

    return [
        Finding(
            title=f"Politique DMARC : p={policy}",
            severity=sev,
            target=domain,
            module=NAME,
            description=(
                "La politique 'none' n'applique aucune action sur les e-mails usurpés."
                if policy == "none"
                else f"Politique DMARC appliquée : {policy}."
            ),
            evidence=record,
            recommendation=(
                "Passer progressivement à p=quarantine puis p=reject."
                if sev.rank >= Severity.LOW.rank
                else ""
            ),
        )
    ]


def _check_caa(domain: str, timeout: float) -> list[Finding]:
    try:
        records = query(domain, "CAA", timeout=timeout)
    except DnsError:
        return []

    if not records:
        return [
            Finding(
                title="Enregistrement CAA absent",
                severity=Severity.LOW,
                target=domain,
                module=NAME,
                description=(
                    "Sans CAA, toute autorité de certification peut émettre un "
                    "certificat pour ce domaine."
                ),
                recommendation="Publier un CAA limitant l'émission à vos AC (ex. letsencrypt.org).",
                references=["https://datatracker.ietf.org/doc/html/rfc8659"],
            )
        ]

    return [
        Finding(
            title="Enregistrements CAA publiés",
            severity=Severity.INFO,
            target=domain,
            module=NAME,
            description=f"{len(records)} enregistrement(s) CAA restreignent l'émission de certificats.",
            evidence="\n".join(records),
        )
    ]


def _enumerate_subdomains(domain: str, timeout: float, log) -> list[Finding]:
    """Résolution d'une courte liste de sous-domaines usuels (pas de brute force)."""
    from concurrent.futures import ThreadPoolExecutor

    def check(sub: str) -> tuple[str, list[str]]:
        fqdn = f"{sub}.{domain}"
        return fqdn, resolves(fqdn, timeout=timeout)

    found: list[tuple[str, list[str]]] = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        for fqdn, ips in pool.map(check, COMMON_SUBDOMAINS):
            if ips:
                found.append((fqdn, ips))

    if not found:
        return []

    for fqdn, ips in found:
        log.good(f"Sous-domaine : {fqdn} → {', '.join(ips[:2])}")

    evidence = "\n".join(f"{fqdn} → {', '.join(ips)}" for fqdn, ips in sorted(found))
    return [
        Finding(
            title=f"Surface exposée : {len(found)} sous-domaine(s) résolus",
            severity=Severity.INFO,
            target=domain,
            module=NAME,
            description=(
                "Ces sous-domaines sont publiquement résolvables et constituent "
                "une surface d'attaque à inventorier."
            ),
            evidence=evidence,
            recommendation=(
                "Vérifiez que chaque entrée est légitime et supprimez les enregistrements "
                "obsolètes (risque de prise de contrôle de sous-domaine)."
            ),
        )
    ]


def run(target: str, ctx) -> list[Finding]:
    log = ctx.logger
    host, _, _ = parse_host(target)
    domain = (host or target).strip().rstrip(".")
    findings: list[Finding] = []
    timeout = ctx.options.get("dns_timeout", 4.0)

    log.info(f"Audit DNS de {domain}…")

    try:
        ns = query(domain, "NS", timeout=timeout)
        if ns:
            log.good(f"Serveurs de noms : {', '.join(ns[:3])}")
            findings.append(
                Finding(
                    title="Serveurs de noms",
                    severity=Severity.INFO,
                    target=domain,
                    module=NAME,
                    description=f"{len(ns)} serveur(s) de noms déclaré(s).",
                    evidence="\n".join(ns),
                )
            )
    except DnsError as e:
        log.error(f"Requête NS impossible : {e}")
        return findings

    findings += _check_spf(domain, timeout)
    findings += _check_dmarc(domain, timeout)
    findings += _check_caa(domain, timeout)

    if ctx.options.get("dns_subdomains", True):
        log.info(f"Test de {len(COMMON_SUBDOMAINS)} sous-domaines usuels…")
        findings += _enumerate_subdomains(domain, timeout, log)

    return findings
