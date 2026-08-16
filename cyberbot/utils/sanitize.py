"""Assainissement des données provenant de sources hostiles.

Tout ce qui vient d'une cible analysée (bannière de service, corps de
réponse, en-tête, enregistrement DNS) est potentiellement malveillant. Ces
données finissent dans le terminal de l'analyste et dans des rapports :
sans traitement, un serveur peut injecter des séquences d'échappement ANSI
pour falsifier l'affichage (masquer une ligne, simuler un « [+] OK »), ou
des caractères nuls / retours chariot pour tronquer une preuve.
"""

from __future__ import annotations

import re
import urllib.parse

# Seuls schémas autorisés dans les liens écrits dans un rapport. Une URL
# 'javascript:' ou 'data:' placée dans un href s'exécuterait au clic.
SAFE_URL_SCHEMES = {"http", "https"}

# Caractères de contrôle C0/C1 sauf tabulation et saut de ligne.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# Séquences ANSI complètes (CSI, OSC…), retirées avant le filtrage générique.
_ANSI_SEQUENCES = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")


def clean_text(value: str, max_length: int | None = None, keep_newlines: bool = True) -> str:
    """Retire séquences ANSI et caractères de contrôle d'une chaîne externe.

    Les caractères retirés sont remplacés par « . » afin que la preuve reste
    lisible et que la longueur observée ne soit pas trompeuse.
    """
    if not value:
        return ""

    text = _ANSI_SEQUENCES.sub("", value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not keep_newlines:
        text = text.replace("\n", " ")
    text = _CONTROL_CHARS.sub(".", text)

    if max_length is not None and len(text) > max_length:
        text = text[:max_length] + "…"
    return text


def clean_line(value: str, max_length: int = 200) -> str:
    """Variante sur une seule ligne, pour l'affichage terminal."""
    return clean_text(value, max_length=max_length, keep_newlines=False).strip()


def safe_url(value: str, max_length: int = 500) -> str | None:
    """Retourne l'URL si elle est sûre à placer dans un lien, sinon None.

    Refuse tout schéma hors http/https ('javascript:', 'data:', 'file:'…),
    ainsi que les caractères de contrôle utilisés pour contourner un filtre
    (ex. 'java\\tscript:alert(1)').
    """
    if not value:
        return None

    candidate = _ANSI_SEQUENCES.sub("", value)
    candidate = _CONTROL_CHARS.sub("", candidate)
    candidate = candidate.replace("\t", "").replace("\n", "").strip()

    if len(candidate) > max_length:
        return None

    try:
        parsed = urllib.parse.urlparse(candidate)
    except ValueError:
        return None

    if parsed.scheme.lower() not in SAFE_URL_SCHEMES:
        return None
    if not parsed.netloc:
        return None
    return candidate
