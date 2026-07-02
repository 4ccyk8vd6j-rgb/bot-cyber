"""Recherche de vulnérabilités connues (CVE) via l'API OSV.

Passif : interroge osv.dev pour un couple paquet@version, ou pour un
identifiant de vulnérabilité (CVE-…, GHSA-…).

Formats de `target` acceptés :
  - "PyPI:requests:2.19.0"   (ecosystem:nom:version)
  - "npm:lodash:4.17.11"
  - "CVE-2021-44228"          (recherche par identifiant)
  - "GHSA-xxxx-xxxx-xxxx"
"""

from __future__ import annotations

import json
import re

from ..core.findings import Finding, Severity
from ..utils.net import http_request

NAME = "cve"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_GET = "https://api.osv.dev/v1/vulns/"


def _severity_from_vuln(vuln: dict) -> Severity:
    for sev in vuln.get("severity", []) or []:
        m = re.search(r"(\d+\.\d+)\s*$", str(sev.get("score", "")))
        if m:
            try:
                return Severity.from_cvss(float(m.group(1)))
            except ValueError:
                pass
    ds = (vuln.get("database_specific") or {}).get("severity", "")
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }.get(str(ds).upper(), Severity.MEDIUM)


def _finding_from_vuln(vuln: dict, target: str) -> Finding:
    vid = vuln.get("id", "?")
    summary = vuln.get("summary") or (vuln.get("details", "") or "")[:300]
    refs = [r.get("url") for r in vuln.get("references", []) if r.get("url")][:6]
    refs.append(f"https://osv.dev/vulnerability/{vid}")
    affected = []
    for a in vuln.get("affected", [])[:5]:
        pkg = a.get("package", {})
        affected.append(f"{pkg.get('ecosystem','?')}:{pkg.get('name','?')}")
    return Finding(
        title=f"{vid} — {vuln.get('summary', 'Vulnérabilité connue')[:80]}",
        severity=_severity_from_vuln(vuln),
        target=target,
        module=NAME,
        description=summary or "Vulnérabilité référencée par OSV.",
        evidence="Paquets affectés : " + (", ".join(dict.fromkeys(affected)) or "—"),
        recommendation="Appliquer le correctif ou mettre à jour vers une version non affectée.",
        references=refs,
        metadata={"aliases": vuln.get("aliases", [])},
    )


def run(target: str, ctx) -> list[Finding]:
    log = ctx.logger
    timeout = ctx.options.get("http_timeout", 10.0)
    findings: list[Finding] = []
    t = target.strip()

    # Cas 1 : identifiant direct (CVE-… / GHSA-…).
    if re.match(r"^(CVE-\d{4}-\d+|GHSA-[\w-]+)$", t, re.IGNORECASE):
        log.info(f"Recherche de l'identifiant {t} sur OSV…")
        resp = http_request(OSV_GET + t, timeout=timeout)
        if resp.status == 200:
            findings.append(_finding_from_vuln(resp.json(), t))
            log.good(f"{t} trouvé.")
        else:
            log.warn(f"{t} introuvable (HTTP {resp.status}).")
        return findings

    # Cas 2 : ecosystem:nom:version.
    parts = t.split(":")
    if len(parts) == 3:
        ecosystem, name, version = parts
        log.info(f"Recherche des CVE pour {name}@{version} ({ecosystem})…")
        payload = json.dumps(
            {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
        ).encode("utf-8")
        resp = http_request(
            OSV_QUERY,
            method="POST",
            headers={"Content-Type": "application/json"},
            data=payload,
            timeout=timeout,
        )
        if resp.status == 200:
            for v in resp.json().get("vulns", []) or []:
                findings.append(_finding_from_vuln(v, f"{name}@{version}"))
            if findings:
                log.warn(f"{len(findings)} vulnérabilité(s) trouvée(s) pour {name}@{version}.")
            else:
                log.good(f"Aucune vulnérabilité connue pour {name}@{version}.")
        else:
            log.error(f"OSV a répondu HTTP {resp.status}.")
        return findings

    log.error(
        "Format invalide. Utilisez 'ecosystem:nom:version' (ex. PyPI:requests:2.19.0) "
        "ou un identifiant 'CVE-…' / 'GHSA-…'."
    )
    return findings
