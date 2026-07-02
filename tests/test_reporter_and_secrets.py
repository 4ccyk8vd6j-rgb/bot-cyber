import json
from pathlib import Path

from cyberbot.core.findings import Finding, FindingsCollection, Severity
from cyberbot.core.reporter import write_all
from cyberbot.modules import secrets_scan
from cyberbot.utils.logging import Logger


class _Ctx:
    def __init__(self, opts=None):
        self.logger = Logger(verbose=False, use_color=False)
        self.options = opts or {}
        self.scope = None


def test_write_all_formats(tmp_path):
    c = FindingsCollection()
    c.add(Finding(title="Test", severity=Severity.HIGH, target="x", module="m",
                  evidence="line1\nline2", recommendation="fix", references=["https://a"]))
    paths = write_all(c, "target", tmp_path)
    for fmt in ("json", "markdown", "html"):
        assert paths[fmt].exists()
    data = json.loads(paths["json"].read_text())
    assert data["total_findings"] == 1
    assert data["highest_severity"] == "high"
    assert "<html" in paths["html"].read_text().lower()


def test_secrets_scan_detects_aws_key(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = secrets_scan.run(str(tmp_path), _Ctx())
    titles = [x.title for x in findings]
    assert any("AWS" in t for t in titles)


def test_secrets_scan_detects_private_key(tmp_path):
    f = tmp_path / "id_rsa"
    f.write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
    findings = secrets_scan.run(str(tmp_path), _Ctx())
    assert any(x.severity is Severity.CRITICAL for x in findings)


def test_secrets_scan_clean_dir(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\nprint('hello world')\n")
    findings = secrets_scan.run(str(tmp_path), _Ctx({"secrets_entropy": False}))
    assert findings == []
