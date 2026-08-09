from cyberbot.cli import build_parser


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
    parser = build_parser()
    args = parser.parse_args(["scan", "host"])
    assert args.modules == "recon,headers,tls"
