from cyberbot.core.findings import Finding, FindingsCollection, Severity


def test_severity_from_cvss():
    assert Severity.from_cvss(9.5) is Severity.CRITICAL
    assert Severity.from_cvss(7.0) is Severity.HIGH
    assert Severity.from_cvss(4.0) is Severity.MEDIUM
    assert Severity.from_cvss(0.1) is Severity.LOW
    assert Severity.from_cvss(0.0) is Severity.INFO


def test_severity_rank_order():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank


def _mk(sev):
    return Finding(title="t", severity=sev, target="x", module="m")


def test_collection_sorting_and_counts():
    c = FindingsCollection()
    c.add(_mk(Severity.LOW))
    c.add(_mk(Severity.CRITICAL))
    c.add(_mk(Severity.MEDIUM))
    items = c.items
    assert items[0].severity is Severity.CRITICAL
    assert len(c) == 3
    assert c.by_severity()["critical"] == 1
    assert c.highest_severity() is Severity.CRITICAL


def test_finding_to_dict():
    f = _mk(Severity.HIGH)
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["title"] == "t"


def test_empty_collection():
    c = FindingsCollection()
    assert c.highest_severity() is Severity.INFO
    assert len(c) == 0
