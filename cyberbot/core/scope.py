"""Gestion du périmètre autorisé (scope).

Ce module est le garde-fou éthique et légal du bot : aucune analyse
active ne doit cibler un hôte hors du périmètre déclaré. C'est ce qui
distingue un outil de sécurité légitime d'un outil d'attaque.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


class ScopeError(Exception):
    """Levée quand une cible est hors périmètre."""


@dataclass
class Scope:
    """Périmètre d'autorisation.

    - `domains` : suffixes de domaines autorisés (ex. "example.com" autorise
      "example.com" et "app.example.com").
    - `hosts` : hôtes/IP exacts autorisés.
    - `cidrs` : plages réseau autorisées (ex. "10.0.0.0/24").
    - `allow_private` : autorise par défaut les adresses privées/loopback
      (utile en labo). Désactivé => refuse les IP publiques hors liste.
    """

    domains: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    allow_private: bool = False

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"Fichier de périmètre introuvable : {p}")
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(
            domains=[d.lower().lstrip(".") for d in data.get("domains", [])],
            hosts=[h.lower() for h in data.get("hosts", [])],
            cidrs=list(data.get("cidrs", [])),
            allow_private=bool(data.get("allow_private", False)),
        )

    @classmethod
    def permissive_localhost(cls) -> "Scope":
        """Périmètre par défaut sûr : uniquement la machine locale."""
        return cls(
            hosts=["localhost", "127.0.0.1", "::1"],
            cidrs=["127.0.0.0/8", "::1/128"],
            allow_private=False,
        )

    # ------------------------------------------------------------------
    def _host_matches_domain(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        return False

    def _ip_in_cidrs(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for cidr in self.cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _resolve(host: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return []
        return sorted({info[4][0] for info in infos})

    # ------------------------------------------------------------------
    def is_allowed(self, target: str) -> bool:
        """Retourne True si `target` (hôte, IP ou URL host) est autorisé."""
        host = target.lower().strip()
        # Retire un éventuel port.
        if host.count(":") == 1 and not host.startswith("["):
            host = host.split(":", 1)[0]

        if host in self.hosts:
            return True
        if self._host_matches_domain(host):
            return True

        # Cible déjà sous forme d'IP.
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        candidate_ips = [host] if is_ip else self._resolve(host)
        for ip in candidate_ips:
            if self._ip_in_cidrs(ip):
                return True
            if self.allow_private:
                try:
                    a = ipaddress.ip_address(ip)
                    if a.is_private or a.is_loopback:
                        return True
                except ValueError:
                    pass
        return False

    def enforce(self, target: str) -> None:
        """Lève ScopeError si la cible n'est pas autorisée."""
        if not self.is_allowed(target):
            raise ScopeError(
                f"Cible hors périmètre : '{target}'. "
                "Ajoutez-la au fichier de périmètre (config/scope.json) "
                "uniquement si vous êtes autorisé à la tester."
            )


def scope_guard(ctx) -> "Callable[[str], bool] | None":
    """Extrait du contexte le contrôle de périmètre à appliquer aux redirections.

    Retourne None si aucun périmètre n'est défini (le client HTTP ne filtrera
    alors pas les sauts de redirection).
    """
    scope = getattr(ctx, "scope", None)
    if scope is None:
        return None
    return scope.is_allowed
