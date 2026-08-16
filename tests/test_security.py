"""Tests de non-régression des correctifs de sécurité.

Chaque test correspond à une faille identifiée puis corrigée. Ils doivent
échouer si l'un des garde-fous est retiré.
"""

import os
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cyberbot.core.findings import Finding, FindingsCollection, Severity
from cyberbot.core.reporter import write_all
from cyberbot.core.scope import Scope, scope_guard
from cyberbot.utils import dns as dnsmod
from cyberbot.utils.net import UnsafeRequestError, http_request
from cyberbot.utils.sanitize import clean_line, clean_text, safe_url


# --------------------------------------------------------------------------
# 1. Contournement de périmètre par redirection (SSRF)
# --------------------------------------------------------------------------

def _serve(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _redirector_to(location):
    class R(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    return R


class _Secret(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Secret.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "6")
        self.end_headers()
        self.wfile.write(b"SECRET")

    def log_message(self, *a):
        pass


def test_redirect_hors_perimetre_est_refuse():
    _Secret.hits.clear()
    victim, victim_url = _serve(_Secret)
    attacker, attacker_url = _serve(_redirector_to(f"{victim_url}/interne"))
    try:
        with pytest.raises(UnsafeRequestError, match="hors périmètre"):
            http_request(attacker_url, timeout=5, is_allowed=lambda host: False)
        # Le point essentiel : l'hôte interdit n'a jamais été contacté.
        assert _Secret.hits == []
    finally:
        attacker.shutdown()
        victim.shutdown()


def test_redirect_dans_le_perimetre_est_suivi():
    _Secret.hits.clear()
    victim, victim_url = _serve(_Secret)
    front, front_url = _serve(_redirector_to(f"{victim_url}/ok"))
    try:
        resp = http_request(front_url, timeout=5, is_allowed=lambda host: True)
        assert resp.status == 200
        assert resp.text == "SECRET"
        assert _Secret.hits == ["/ok"]
    finally:
        front.shutdown()
        victim.shutdown()


def test_boucle_de_redirections_est_bornee():
    holder = {}

    class Loop(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", holder["url"])
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    server, url = _serve(Loop)
    holder["url"] = url
    try:
        with pytest.raises(UnsafeRequestError, match="Trop de redirections"):
            http_request(url, timeout=5, is_allowed=lambda h: True)
    finally:
        server.shutdown()


def test_redirect_vers_schema_interdit_est_refuse():
    server, url = _serve(_redirector_to("file:///etc/passwd"))
    try:
        with pytest.raises(UnsafeRequestError, match="Schéma"):
            http_request(url, timeout=5, is_allowed=lambda h: True)
    finally:
        server.shutdown()


# --------------------------------------------------------------------------
# 2. Schémas d'URL non-HTTP
# --------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.com/x",
    "gopher://example.com",
    "/chemin/relatif",
])
def test_schemas_non_http_refuses(url):
    with pytest.raises(UnsafeRequestError):
        http_request(url, timeout=2)


# --------------------------------------------------------------------------
# 3. Liens dangereux dans les rapports
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "java\tscript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "//evil.example",
])
def test_safe_url_rejette_les_schemas_dangereux(bad):
    assert safe_url(bad) is None


def test_safe_url_conserve_http_et_https():
    assert safe_url("https://ok.example/a?b=1") == "https://ok.example/a?b=1"
    assert safe_url("http://ok.example") == "http://ok.example"


def test_finding_filtre_les_references_dangereuses():
    f = Finding(
        title="t", severity=Severity.INFO, target="x", module="m",
        references=["javascript:alert(1)", "https://ok.example", "data:x"],
    )
    assert f.references == ["https://ok.example"]


def test_rapport_html_ne_contient_aucun_lien_executable(tmp_path):
    c = FindingsCollection()
    c.add(Finding(title="T", severity=Severity.HIGH, target="x", module="m",
                  references=["javascript:alert(1)", "https://ok.example"]))
    paths = write_all(c, "cible", tmp_path)
    html = paths["html"].read_text()
    md = paths["markdown"].read_text()
    assert "javascript:" not in html
    assert "javascript:" not in md
    assert "https://ok.example" in html
    assert "Content-Security-Policy" in html


# --------------------------------------------------------------------------
# 4. Caractères de contrôle issus de serveurs hostiles
# --------------------------------------------------------------------------

@pytest.mark.parametrize("payload,interdit", [
    ("SSH-2.0\x1b[31mFAUX\x1b[0m", "\x1b["),
    ("reel\x1b[2K\x1b[1Gfalsifie", "\x1b"),
    ("a\x1b]0;titre\x07b", "\x07"),
    ("avant\x00apres", "\x00"),
])
def test_clean_text_retire_les_sequences_de_controle(payload, interdit):
    assert interdit not in clean_text(payload)


def test_clean_text_preserve_tabulation_et_saut_de_ligne():
    assert clean_text("a\tb\nc") == "a\tb\nc"


def test_clean_line_reduit_a_une_seule_ligne():
    assert "\n" not in clean_line("a\nb\nc")


def test_finding_assainit_tous_les_champs_externes():
    f = Finding(
        title="Titre\x1b[2K\x1b[1Gfalsifie",
        severity=Severity.HIGH,
        target="ho\x00te",
        module="m",
        description="desc\x1b[31m",
        evidence="preuve\x1b[0m\x07",
        recommendation="reco\x00",
    )
    for value in (f.title, f.target, f.description, f.evidence, f.recommendation):
        assert "\x1b" not in value
        assert "\x00" not in value
        assert "\x07" not in value


def test_finding_borne_la_taille_des_champs():
    f = Finding(title="t", severity=Severity.INFO, target="x", module="m",
                evidence="A" * 50_000)
    assert len(f.evidence) <= 8_001


def test_rapport_ne_contient_pas_de_sequence_ansi(tmp_path):
    c = FindingsCollection()
    c.add(Finding(title="T\x1b[31m", severity=Severity.HIGH, target="x", module="m",
                  evidence="corps\x1b[2Kfalsifie"))
    paths = write_all(c, "cible", tmp_path)
    for path in paths.values():
        assert "\x1b" not in path.read_text()


# --------------------------------------------------------------------------
# 5. Permissions des rapports
# --------------------------------------------------------------------------

def test_rapports_lisibles_par_le_seul_proprietaire(tmp_path):
    c = FindingsCollection()
    c.add(Finding(title="T", severity=Severity.HIGH, target="x", module="m"))
    out = tmp_path / "rapports"
    paths = write_all(c, "cible", out)
    for path in paths.values():
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, f"{path.name} est en {oct(mode)}"
    assert os.stat(out).st_mode & 0o777 == 0o700


def test_rapport_preexistant_est_reprotege(tmp_path):
    """Un fichier déjà présent en 0644 doit être ramené à 0600."""
    out = tmp_path / "rapports"
    out.mkdir()
    c = FindingsCollection()
    c.add(Finding(title="T", severity=Severity.HIGH, target="x", module="m"))
    first = write_all(c, "cible", out)
    victim = first["json"]
    os.chmod(victim, 0o644)

    from cyberbot.core.reporter import write_json
    write_json(c, "cible", victim)
    assert os.stat(victim).st_mode & 0o777 == 0o600


# --------------------------------------------------------------------------
# 6. Réponses DNS forgées
# --------------------------------------------------------------------------

def _fake_dns_server(response_builder):
    """Petit serveur DNS local qui répond ce qu'on lui dit de répondre."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def serve():
        try:
            data, addr = sock.recvfrom(4096)
            sock.sendto(response_builder(data), addr)
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return sock, port


def _build_response(query_bytes, *, name=b"\x07example\x03com\x00", qtype=1, txn=None):
    txn_id = struct.unpack("!H", query_bytes[:2])[0] if txn is None else txn
    header = struct.pack("!HHHHHH", txn_id, 0x8180, 1, 1, 0, 0)
    question = name + struct.pack("!HH", qtype, 1)
    answer = name + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([1, 2, 3, 4])
    return header + question + answer


def test_dns_accepte_une_reponse_coherente():
    """Chemin nominal : garantit que les tests suivants échouent pour la bonne raison."""
    sock, port = _fake_dns_server(lambda q: _build_response(q))
    try:
        result = dnsmod.query("example.com", "A", resolver="127.0.0.1", timeout=2, port=port)
    finally:
        sock.close()
    assert result == ["1.2.3.4"]


def test_dns_rejette_une_question_qui_ne_correspond_pas():
    """Une réponse portant sur un autre nom ne doit pas être acceptée."""
    sock, port = _fake_dns_server(
        lambda q: _build_response(q, name=b"\x04evil\x03com\x00")
    )
    try:
        with pytest.raises(dnsmod.DnsError, match="question renvoyée"):
            dnsmod.query("example.com", "A", resolver="127.0.0.1", timeout=2, port=port)
    finally:
        sock.close()


def test_dns_rejette_un_type_qui_ne_correspond_pas():
    sock, port = _fake_dns_server(lambda q: _build_response(q, qtype=16))
    try:
        with pytest.raises(dnsmod.DnsError, match="type renvoyé"):
            dnsmod.query("example.com", "A", resolver="127.0.0.1", timeout=2, port=port)
    finally:
        sock.close()


def test_dns_rejette_un_identifiant_de_transaction_incorrect():
    sock, port = _fake_dns_server(lambda q: _build_response(q, txn=0x1234))
    try:
        with pytest.raises(dnsmod.DnsError, match="transaction"):
            dnsmod.query("example.com", "A", resolver="127.0.0.1", timeout=2, port=port)
    finally:
        sock.close()


def test_dns_rejette_un_rdlength_mensonger():
    """Un rdlength supérieur aux données restantes ne doit pas être exploité."""
    def forge(q):
        txn_id = struct.unpack("!H", q[:2])[0]
        name = b"\x07example\x03com\x00"
        header = struct.pack("!HHHHHH", txn_id, 0x8180, 1, 1, 0, 0)
        question = name + struct.pack("!HH", 1, 1)
        # Annonce 4000 octets de données mais n'en fournit que 4.
        answer = name + struct.pack("!HHIH", 1, 1, 60, 4000) + bytes([1, 2, 3, 4])
        return header + question + answer

    sock, port = _fake_dns_server(forge)
    try:
        result = dnsmod.query("example.com", "A", resolver="127.0.0.1", timeout=2, port=port)
    finally:
        sock.close()
    assert result == []


# --------------------------------------------------------------------------
# 7. Le garde de périmètre est bien propagé
# --------------------------------------------------------------------------

class _Ctx:
    def __init__(self, scope):
        self.scope = scope
        self.options = {}


def test_scope_guard_reflete_le_perimetre():
    guard = scope_guard(_Ctx(Scope(domains=["example.com"])))
    assert guard("example.com") is True
    assert guard("evil.example") is False


def test_scope_guard_absent_si_pas_de_perimetre():
    assert scope_guard(_Ctx(None)) is None
