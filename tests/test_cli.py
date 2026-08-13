from cyberbot.cli import _COMMAND_MAP, build_parser
from cyberbot.modules import ACTIVE_MODULES, PASSIVE_MODULES, REGISTRY


def test_global_option_after_subcommand():
    """Les options globales doivent être acceptées APRÈS la sous-commande."""
    parser = build_parser()
    args = parser.parse_args(
        ["scan", "example.com", "--report-dir", "/tmp/out", "--no-report", "--allow-any"]
    )
    assert args.command == "scan"
    assert args.target == "example.com"
    assert args.report_dir == "/tmp/out"
    assert args.no_report is True
    assert args.allow_any is True


def test_global_option_before_subcommand():
    """Et AUSSI avant la sous-commande."""
    parser = build_parser()
    args = parser.parse_args(
        ["--report-dir", "/tmp/out", "--verbose", "web", "example.com"]
    )
    assert args.command == "web"
    assert args.report_dir == "/tmp/out"
    assert args.verbose is True


def test_defaults_absent_use_getattr_fallback():
    """Sans option fournie, l'attribut est absent (SUPPRESS) -> géré par getattr."""
    parser = build_parser()
    args = parser.parse_args(["secrets", "."])
    assert args.command == "secrets"
    assert not hasattr(args, "report_dir")
    assert getattr(args, "report_dir", "reports") == "reports"


def test_scan_modules_default():
    """Le scan par défaut doit couvrir tous les modules enregistrés pertinents."""
    parser = build_parser()
    args = parser.parse_args(["scan", "host"])
    names = [m.strip() for m in args.modules.split(",")]
    assert set(names) <= set(REGISTRY), "modules par défaut inconnus du registre"
    for expected in ("recon", "headers", "tls", "cors", "exposure", "dns"):
        assert expected in names


def test_every_registered_module_has_subcommand():
    """Chaque module du registre doit être atteignable depuis la CLI."""
    reachable = set()
    for mods, _ in _COMMAND_MAP.values():
        reachable.update(mods)
    parser = build_parser()
    reachable.update(m.strip() for m in parser.parse_args(["scan", "h"]).modules.split(","))
    assert set(REGISTRY) <= reachable


def test_active_and_passive_modules_partition_registry():
    assert ACTIVE_MODULES | PASSIVE_MODULES == set(REGISTRY)
    assert not (ACTIVE_MODULES & PASSIVE_MODULES)
