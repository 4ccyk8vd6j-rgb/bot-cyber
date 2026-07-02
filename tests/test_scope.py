from cyberbot.core.scope import Scope, ScopeError


def test_domain_suffix_match():
    s = Scope(domains=["example.com"])
    assert s.is_allowed("example.com")
    assert s.is_allowed("app.example.com")
    assert not s.is_allowed("evil.com")
    assert not s.is_allowed("notexample.com")


def test_exact_host_match():
    s = Scope(hosts=["localhost", "127.0.0.1"])
    assert s.is_allowed("localhost")
    assert s.is_allowed("127.0.0.1")
    assert not s.is_allowed("192.168.1.1")


def test_cidr_match():
    s = Scope(cidrs=["10.0.0.0/24"])
    assert s.is_allowed("10.0.0.5")
    assert not s.is_allowed("10.0.1.5")


def test_allow_private():
    s = Scope(allow_private=True)
    assert s.is_allowed("192.168.1.10")
    assert s.is_allowed("127.0.0.1")


def test_port_stripped():
    s = Scope(hosts=["example.com"])
    assert s.is_allowed("example.com:8080")


def test_enforce_raises():
    s = Scope(domains=["example.com"])
    try:
        s.enforce("evil.com")
    except ScopeError:
        return
    raise AssertionError("ScopeError attendue")


def test_permissive_localhost():
    s = Scope.permissive_localhost()
    assert s.is_allowed("127.0.0.1")
    assert not s.is_allowed("8.8.8.8")
