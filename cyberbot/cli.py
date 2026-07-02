"""Interface en ligne de commande de CyberBot."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, modules
from .core.findings import FindingsCollection, Severity
from .core.reporter import write_all
from .core.scope import Scope, ScopeError
from .utils.logging import Logger

BANNER = r"""
   ____      _               ____        _
  / ___|   _| |__   ___ _ __| __ )  ___ | |_
 | |  | | | | '_ \ / _ \ '__|  _ \ / _ \| __|
 | |__| |_| | |_) |  __/ |  | |_) | (_) | |_
  \____\__, |_.__/ \___|_|  |____/ \___/ \__|
       |___/   analyse de sécurité défensive · v{ver}
"""


@dataclass
class Context:
    """Contexte partagé passé à chaque module."""

    logger: Logger
    scope: Scope
    options: dict[str, Any] = field(default_factory=dict)


def _print_summary(log: Logger, findings: FindingsCollection) -> None:
    log.section("Synthèse")
    counts = findings.by_severity()
    labels = {
        "critical": "Critique",
        "high": "Élevée",
        "medium": "Moyenne",
        "low": "Faible",
        "info": "Info",
    }
    for sev in reversed(list(Severity)):
        n = counts[sev.value]
        if n:
            msg = f"{labels[sev.value]:<9}: {n}"
            if sev.rank >= Severity.HIGH.rank:
                log.warn(msg)
            else:
                log.info(msg)
    log.info(f"Total     : {len(findings)}")


def _run_modules(
    module_names: list[str],
    target: str,
    ctx: Context,
    require_scope: bool,
) -> FindingsCollection:
    findings = FindingsCollection()
    log = ctx.logger

    for name in module_names:
        is_active = name in modules.ACTIVE_MODULES
        if is_active and require_scope:
            try:
                ctx.scope.enforce(target)
            except ScopeError as e:
                log.error(str(e))
                log.error(f"Module '{name}' ignoré (hors périmètre).")
                continue

        log.section(f"Module : {name}")
        try:
            mod = modules.load(name)
            results = mod.run(target, ctx)
            findings.extend(results)
            log.debug(f"{len(results)} finding(s) depuis '{name}'.")
        except Exception as e:  # noqa: BLE001
            log.error(f"Le module '{name}' a échoué : {e}")
            if ctx.logger.verbose:
                import traceback
                traceback.print_exc()

    return findings


def _resolve_scope(args) -> Scope:
    if args.scope:
        return Scope.load(args.scope)
    if getattr(args, "allow_any", False):
        # Autorise tout : réservé aux cibles dont VOUS êtes responsable.
        return Scope(domains=[], hosts=[], cidrs=["0.0.0.0/0", "::/0"], allow_private=True)
    default = Path("config/scope.json")
    if default.exists():
        return Scope.load(default)
    return Scope.permissive_localhost()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberbot",
        description="CyberBot — analyse de vulnérabilités et de sécurité (usage autorisé uniquement).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  cyberbot scan example.com --scope config/scope.json\n"
            "  cyberbot web https://example.com\n"
            "  cyberbot deps ./mon-projet\n"
            "  cyberbot secrets ./mon-projet\n"
            "  cyberbot cve PyPI:requests:2.19.0\n"
            "  cyberbot cve CVE-2021-44228\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"CyberBot {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="Sortie détaillée.")
    p.add_argument("--no-banner", action="store_true", help="Ne pas afficher la bannière.")
    p.add_argument("--scope", help="Fichier JSON de périmètre autorisé.")
    p.add_argument(
        "--report-dir", default="reports", help="Dossier de sortie des rapports (défaut: reports)."
    )
    p.add_argument(
        "--no-report", action="store_true", help="Ne pas écrire de fichiers de rapport."
    )

    sub = p.add_subparsers(dest="command", required=True)

    # scan : lance l'ensemble des modules actifs sur une cible réseau.
    sp = sub.add_parser("scan", help="Analyse complète d'un hôte (recon + headers + tls).")
    sp.add_argument("target", help="Hôte, IP ou URL cible (doit être dans le périmètre).")
    sp.add_argument(
        "--allow-any",
        action="store_true",
        help="Désactive le contrôle de périmètre (uniquement vos propres actifs !).",
    )
    sp.add_argument(
        "--modules",
        default="recon,headers,tls",
        help="Liste de modules à exécuter (défaut: recon,headers,tls).",
    )

    wp = sub.add_parser("web", help="Analyse des en-têtes/cookies de sécurité HTTP.")
    wp.add_argument("target", help="URL ou hôte cible.")
    wp.add_argument("--allow-any", action="store_true", help="Désactive le contrôle de périmètre.")

    tp = sub.add_parser("tls", help="Contrôle de la configuration TLS/certificat.")
    tp.add_argument("target", help="Hôte[:port] cible (443 par défaut).")
    tp.add_argument("--allow-any", action="store_true", help="Désactive le contrôle de périmètre.")

    rp = sub.add_parser("recon", help="Reconnaissance DNS + scan de ports.")
    rp.add_argument("target", help="Hôte ou IP cible.")
    rp.add_argument("--allow-any", action="store_true", help="Désactive le contrôle de périmètre.")

    dp = sub.add_parser("deps", help="Audit des dépendances (OSV) d'un projet local.")
    dp.add_argument("target", help="Chemin du projet (contenant requirements.txt/package-lock.json).")

    ssp = sub.add_parser("secrets", help="Recherche de secrets codés en dur dans un dossier.")
    ssp.add_argument("target", help="Chemin du dossier à analyser.")

    cp = sub.add_parser("cve", help="Recherche de CVE via OSV.")
    cp.add_argument("target", help="'ecosystem:nom:version' ou 'CVE-…' / 'GHSA-…'.")

    return p


# command -> (modules, require_scope)
_COMMAND_MAP = {
    "web": (["headers"], True),
    "tls": (["tls"], True),
    "recon": (["recon"], True),
    "deps": (["deps"], False),
    "secrets": (["secrets"], False),
    "cve": (["cve"], False),
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    log = Logger(verbose=args.verbose)
    if not args.no_banner:
        print(BANNER.format(ver=__version__))

    try:
        scope = _resolve_scope(args)
    except ScopeError as e:
        log.error(str(e))
        return 2

    ctx = Context(logger=log, scope=scope, options={"verbose": args.verbose})

    if args.command == "scan":
        module_names = [m.strip() for m in args.modules.split(",") if m.strip()]
        require_scope = not getattr(args, "allow_any", False)
    else:
        module_names, require_scope = _COMMAND_MAP[args.command]
        if getattr(args, "allow_any", False):
            require_scope = False

    if require_scope:
        log.info("Contrôle de périmètre ACTIF. Seules les cibles autorisées seront analysées.")
    else:
        log.warn("Contrôle de périmètre DÉSACTIVÉ — assurez-vous d'être autorisé sur la cible.")

    target = args.target
    findings = _run_modules(module_names, target, ctx, require_scope)

    _print_summary(log, findings)

    if not args.no_report and len(findings):
        paths = write_all(findings, target, args.report_dir)
        log.section("Rapports générés")
        for fmt, path in paths.items():
            log.good(f"{fmt:<8}: {path}")

    # Code de sortie : 1 si au moins un finding High/Critical, sinon 0.
    if findings.highest_severity().rank >= Severity.HIGH.rank:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
