import struct

import pytest

from cyberbot.utils import dns as dnsmod


def test_encode_name_roundtrip():
    encoded = dnsmod._encode_name("www.example.com")
    assert encoded == b"\x03www\x07example\x03com\x00"


def test_encode_name_rejects_long_label():
    with pytest.raises(dnsmod.DnsError):
        dnsmod._encode_name("a" * 64 + ".com")


def test_decode_name_simple():
    msg = b"\x03www\x07example\x03com\x00"
    name, offset = dnsmod._decode_name(msg, 0)
    assert name == "www.example.com"
    assert offset == len(msg)


def test_decode_name_with_compression_pointer():
    # "example.com" à l'offset 0, puis "www" + pointeur vers l'offset 0.
    base = b"\x07example\x03com\x00"
    msg = base + b"\x03www\xc0\x00"
    name, offset = dnsmod._decode_name(msg, len(base))
    assert name == "www.example.com"
    assert offset == len(msg)


def test_decode_name_detects_pointer_loop():
    msg = b"\xc0\x00"  # pointeur vers lui-même
    with pytest.raises(dnsmod.DnsError):
        dnsmod._decode_name(msg, 0)


def test_parse_rdata_a_record():
    rdata = bytes([93, 184, 216, 34])
    assert dnsmod._parse_rdata(dnsmod.QTYPE["A"], rdata, 0, 4) == "93.184.216.34"


def test_parse_rdata_txt_record():
    payload = b"\x0bv=spf1 -all"
    assert dnsmod._parse_rdata(dnsmod.QTYPE["TXT"], payload, 0, len(payload)) == "v=spf1 -all"


def test_parse_rdata_mx_record():
    payload = struct.pack("!H", 10) + b"\x04mail\x03com\x00"
    assert dnsmod._parse_rdata(dnsmod.QTYPE["MX"], payload, 0, len(payload)) == "10 mail.com"


def test_query_rejects_unknown_record_type():
    with pytest.raises(dnsmod.DnsError):
        dnsmod.query("example.com", "NOPE")


def test_system_resolvers_never_empty():
    assert dnsmod.system_resolvers()
