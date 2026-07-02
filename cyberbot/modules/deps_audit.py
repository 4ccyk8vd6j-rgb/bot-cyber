"""Audit des dépendances via l'API publique OSV (osv.dev).

Passif : lit des fichiers de manifeste locaux et interroge OSV.
Aucune donnée sensible n'est envoyée (seulement nom + version de paquet).
Écosystèmes supportés : PyPI (requirements.txt), npm (package-lock.json).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.findings import Finding, Severity
from ..utils.net import http_request

NAME = "deps"
OSV_API = "https://api.osv.dev/v1/query"


def _parse_requirements(path: Path) -> list[tuple[str, str, str]]:
    """Retourne [(ecosystem, name, version)] pour requirements.txt."""
    out: list[tuple[str, str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
        if m:
            out.append(("PyPI", m.group(1), m.group(2)))
    return out


def _parse_package_lock(path: Path) -> list[tuple[str, str, str]]:
    """Retourne [(ecosystem, name, version)] pour package-lock.json (v2/v3)."""
    out: list[tuple[str, str, str]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return out
    packages = data.get("packages") or {}
    for pkg_path, meta in packages.items():
        if not pkg_path:  # racine
            continue
        name = pkg_path.split("node_modules/")[-1]
        version = meta.get("version")
        if name and version:
            out.append(("npm", name, version))
    # Repli sur l'ancien format "dependencies".
    if not out:
        for name, meta in (data.get("dependencies") or {}).items():
            v = meta.get("version") if isinstance(meta, dict) else None
            if v:
                out.append(("npm", name, v))
    return out


def _discover(project: Path) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    req = project / "requirements.txt"
    if req.exists():
        deps += _parse_requirements(req)
    lock = project / "package-lock.json"
    if lock.exists():
        deps += _parse_package_lock(lock)
    return deps


def _query_osv(ecosystem: str, name: str, version: str, timeout: float) -> list[dict]:
    payload = json.dumps(
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    ).encode("utf-8")
    resp = http_request(
        OSV_API,
        method="POST",
        headers={"Content-Type": "application/json"},
        data=payload,
        timeout=timeout,
    )
    if resp.status != 200:
        return []
    return resp.json().get("vulns", []) or []


def _severity_from_vuln(vuln: dict) -> Severity:
    # OSV expose parfois database_specific.severity ou un score CVSS.
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "")
        m = re.search(r"/?(\d+\.\d+)$", str(score))
        if m:
            try:
                return Severity.from_cvss(float(m.group(1)))
            except ValueError:
                pass
    ds = (vuln.get("database_specific") or {}).get("severity", "")
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(str(ds).upper(), Severity.MEDIUM)


def run(target: str, ctx) -> list[Finding]:
    """`target` est ici un chemin de projet local à auditer."""
    log = ctx.logger
    project = Path(target).expanduser().resolve()
    findings: list[Finding] = []

    if not project.exists():
        log.error(f"Chemin de projet introuvable : {project}")
        return findings

    deps = _discover(project)
    if not deps:
        log.warn("Aucun manifeste supporté trouvé (requirements.txt / package-lock.json).")
        return findings

    log.info(f"{len(deps)} dépendance(s) à vérifier via OSV…")
    timeout = ctx.options.get("http_timeout", 10.0)
    vuln_count = 0
    query_failures = 0

    for ecosystem, name, version in deps:
        try:
            vulns = _query_osv(ecosystem, name, version, timeout)
        except Exception as e:  # noqa: BLE001
            query_failures += 1
            log.debug(f"OSV a échoué pour {name}=={version} : {e}")
            continue
        for v in vulns:
            vuln_count += 1
            vid = v.get("id", "?")
            aliases = v.get("aliases", [])
            summary = v.get("summary") or v.get("details", "")[:200]
            sev = _severity_from_vuln(v)
            refs = [r.get("url") for r in v.get("references", []) if r.get("url")][:5]
            refs.append(f"https://osv.dev/vulnerability/{vid}")
            log.warn(f"{name}=={version} vulnérable : {vid} ({sev.value})")
            findings.append(
                Finding(
                    title=f"Dépendance vulnérable : {name} {version} ({vid})",
                    severity=sev,
                    target=str(project),
                    module=NAME,
                    description=summary or "Vulnérabilité connue référencée par OSV.",
                    evidence=f"{ecosystem} · {name}=={version}\nAlias : {', '.join(aliases) or '—'}",
                    recommendation="Mettre à jour vers une version corrigée (voir références).",
                    references=refs,
                    metadata={"ecosystem": ecosystem, "package": name, "version": version},
                )
            )

    if query_failures == len(deps):
        log.error(
            "Toutes les requêtes OSV ont échoué (réseau bloqué ou api.osv.dev "
            "inaccessible) : résultat non concluant, pas 'aucune vulnérabilité'."
        )
        findings.append(
            Finding(
                title="Audit des dépendances non concluant (OSV injoignable)",
                severity=Severity.INFO,
                target=str(project),
                module=NAME,
                description="Aucune requête OSV n'a abouti ; impossible de conclure.",
                recommendation="Vérifiez l'accès réseau à https://api.osv.dev puis relancez.",
            )
        )
    elif vuln_count == 0:
        note = ""
        if query_failures:
            note = f" ({query_failures} requête(s) en échec, résultat partiel)"
        log.good(f"Aucune vulnérabilité connue dans les dépendances analysées.{note}")
    return findings
