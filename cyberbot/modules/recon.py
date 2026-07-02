"""Reconnaissance passive/active légère : DNS + scan de ports courants.

⚠️ Actif : ne cible que des hôtes du périmètre autorisé.
Le scan est un simple connect() TCP (pas de SYN furtif, pas d'évasion).
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.findings import Finding, Severity
from ..utils.net import grab_banner, parse_host

NAME = "recon"

# Ports courants et service attendu.
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Services considérés à risque s'ils sont exposés (clair / admin).
RISKY_SERVICES = {
    "telnet": (Severity.HIGH, "Protocole en clair, à remplacer par SSH."),
    "ftp": (Severity.MEDIUM, "FTP transmet les identifiants en clair ; préférez SFTP/FTPS."),
    "rdp": (Severity.MEDIUM, "RDP exposé : restreindre par VPN/liste blanche."),
    "smb": (Severity.HIGH, "SMB exposé sur Internet : surface d'attaque majeure."),
    "redis": (Severity.HIGH, "Redis souvent sans auth : ne jamais exposer publiquement."),
    "mongodb": (Severity.HIGH, "MongoDB exposé : risque d'accès non authentifié."),
    "elasticsearch": (Severity.HIGH, "Elasticsearch exposé : risque de fuite de données."),
    "mysql": (Severity.MEDIUM, "Base de données exposée : restreindre l'accès réseau."),
    "postgresql": (Severity.MEDIUM, "Base de données exposée : restreindre l'accès réseau."),
}


def _scan_port(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def run(target: str, ctx) -> list[Finding]:
    log = ctx.logger
    host, port, _ = parse_host(target)
    host = host or target
    findings: list[Finding] = []

    # Résolution DNS.
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        log.good(f"{host} résout vers : {', '.join(ips)}")
        findings.append(
            Finding(
                title="Résolution DNS",
                severity=Severity.INFO,
                target=host,
                module=NAME,
                description=f"L'hôte résout vers {len(ips)} adresse(s).",
                evidence="\n".join(ips),
            )
        )
    except socket.gaierror as e:
        log.error(f"Résolution DNS impossible pour {host} : {e}")
        return findings

    ports = [port] if port else sorted(COMMON_PORTS)
    timeout = ctx.options.get("port_timeout", 2.0)
    workers = ctx.options.get("port_workers", 50)

    log.info(f"Scan de {len(ports)} port(s) sur {host} (connect TCP)…")
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futs):
            res = fut.result()
            if res is not None:
                open_ports.append(res)

    open_ports.sort()
    for p in open_ports:
        service = COMMON_PORTS.get(p, "inconnu")
        banner = grab_banner(host, p, timeout=timeout)
        log.good(f"Port {p}/tcp ouvert ({service})" + (f" — {banner}" if banner else ""))

        if service in RISKY_SERVICES:
            sev, reco = RISKY_SERVICES[service]
            findings.append(
                Finding(
                    title=f"Service potentiellement sensible exposé : {service} ({p}/tcp)",
                    severity=sev,
                    target=host,
                    module=NAME,
                    description=f"Le port {p} ({service}) accepte des connexions.",
                    evidence=banner or f"Port {p}/tcp ouvert",
                    recommendation=reco,
                )
            )
        else:
            findings.append(
                Finding(
                    title=f"Port ouvert : {p}/tcp ({service})",
                    severity=Severity.INFO,
                    target=host,
                    module=NAME,
                    description=f"Service détecté : {service}.",
                    evidence=banner or f"Port {p}/tcp ouvert",
                )
            )

    if not open_ports:
        log.info("Aucun port courant ouvert détecté.")

    return findings
