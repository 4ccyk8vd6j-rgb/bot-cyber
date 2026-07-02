"""Modules d'analyse. Chaque module expose `run(target, ctx) -> list[Finding]`."""

from importlib import import_module

# Nom logique -> chemin du module Python.
REGISTRY = {
    "recon": "cyberbot.modules.recon",
    "headers": "cyberbot.modules.web_headers",
    "tls": "cyberbot.modules.tls_check",
    "deps": "cyberbot.modules.deps_audit",
    "secrets": "cyberbot.modules.secrets_scan",
    "cve": "cyberbot.modules.cve_lookup",
}

# Modules "actifs" (touchent une cible réseau distante -> exigent le scope).
ACTIVE_MODULES = {"recon", "headers", "tls"}

# Modules "passifs" (analysent des données locales -> pas de scope requis).
PASSIVE_MODULES = {"deps", "secrets", "cve"}


def load(name: str):
    if name not in REGISTRY:
        raise KeyError(f"Module inconnu : {name}")
    return import_module(REGISTRY[name])
