"""Client DNS minimal (UDP) basé uniquement sur la bibliothèque standard.

Permet d'interroger des enregistrements que `socket` ne sait pas récupérer
(TXT, MX, NS, CNAME, CAA) sans introduire de dépendance externe.
"""

from __future__ import annotations

import random
import socket
import struct
from pathlib import Path

# Types d'enregistrements supportés.
QTYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "CAA": 257,
}

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


class DnsError(Exception):
    """Échec d'une requête DNS."""


def system_resolvers() -> list[str]:
    """Lit les serveurs DNS de /etc/resolv.conf, avec repli sur des publics."""
    servers: list[str] = []
    resolv = Path("/etc/resolv.conf")
    if resolv.exists():
        try:
            for line in resolv.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
        except OSError:
            pass
    return servers or list(DEFAULT_RESOLVERS)


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        data = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if len(data) > 63:
            raise DnsError(f"Label DNS trop long : {label}")
        out += bytes([len(data)]) + data
    return out + b"\x00"


def _decode_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Décode un nom (gère la compression par pointeur). Retourne (nom, offset_suivant)."""
    labels: list[str] = []
    jumped = False
    next_offset = offset
    hops = 0

    while True:
        if offset >= len(msg):
            raise DnsError("Message DNS tronqué")
        length = msg[offset]

        if length & 0xC0 == 0xC0:  # pointeur de compression
            if offset + 1 >= len(msg):
                raise DnsError("Pointeur DNS tronqué")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            hops += 1
            if hops > 20:
                raise DnsError("Boucle de compression DNS")
            continue

        offset += 1
        if length == 0:
            if not jumped:
                next_offset = offset
            break
        labels.append(msg[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), next_offset


def _parse_rdata(rtype: int, msg: bytes, offset: int, rdlength: int) -> str | None:
    end = offset + rdlength

    if rtype == QTYPE["A"] and rdlength == 4:
        return socket.inet_ntop(socket.AF_INET, msg[offset:end])
    if rtype == QTYPE["AAAA"] and rdlength == 16:
        return socket.inet_ntop(socket.AF_INET6, msg[offset:end])
    if rtype in (QTYPE["NS"], QTYPE["CNAME"]):
        name, _ = _decode_name(msg, offset)
        return name
    if rtype == QTYPE["MX"]:
        priority = struct.unpack("!H", msg[offset:offset + 2])[0]
        name, _ = _decode_name(msg, offset + 2)
        return f"{priority} {name}"
    if rtype == QTYPE["TXT"]:
        parts: list[str] = []
        pos = offset
        while pos < end:
            slen = msg[pos]
            pos += 1
            parts.append(msg[pos:pos + slen].decode("utf-8", errors="replace"))
            pos += slen
        return "".join(parts)
    if rtype == QTYPE["CAA"] and rdlength >= 2:
        tag_len = msg[offset + 1]
        tag = msg[offset + 2:offset + 2 + tag_len].decode("ascii", errors="replace")
        value = msg[offset + 2 + tag_len:end].decode("ascii", errors="replace")
        return f"{tag} {value}"
    return None


def query(
    name: str,
    record: str = "A",
    resolver: str | None = None,
    timeout: float = 3.0,
) -> list[str]:
    """Interroge le DNS et retourne les valeurs de la section réponse.

    Lève DnsError en cas d'échec réseau ; retourne [] si aucun enregistrement.
    """
    record = record.upper()
    if record not in QTYPE:
        raise DnsError(f"Type d'enregistrement non supporté : {record}")
    rtype = QTYPE[record]

    servers = [resolver] if resolver else system_resolvers()
    txn_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)  # RD=1
    question = _encode_name(name) + struct.pack("!HH", rtype, 1)
    packet = header + question

    last_error: Exception | None = None
    for server in servers:
        try:
            family = socket.AF_INET6 if ":" in server else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (server, 53))
                data, _ = sock.recvfrom(4096)
        except OSError as e:
            last_error = e
            continue

        if len(data) < 12:
            last_error = DnsError("Réponse DNS trop courte")
            continue

        resp_id, _flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
        if resp_id != txn_id:
            last_error = DnsError("ID de transaction DNS incohérent")
            continue

        offset = 12
        for _ in range(qdcount):  # saute la section question
            _, offset = _decode_name(data, offset)
            offset += 4

        results: list[str] = []
        for _ in range(ancount):
            try:
                _, offset = _decode_name(data, offset)
                rr_type, _rr_class, _ttl, rdlength = struct.unpack(
                    "!HHIH", data[offset:offset + 10]
                )
                offset += 10
                value = _parse_rdata(rr_type, data, offset, rdlength)
                offset += rdlength
            except (struct.error, DnsError):
                break
            if value is not None and rr_type == rtype:
                results.append(value)
        return results

    raise DnsError(f"Aucun résolveur n'a répondu pour {name}/{record} : {last_error}")


def resolves(name: str, timeout: float = 3.0) -> list[str]:
    """Raccourci : retourne les adresses A d'un nom ([] s'il n'existe pas)."""
    try:
        return query(name, "A", timeout=timeout)
    except DnsError:
        return []
