"""Détection de secrets codés en dur dans un dépôt local.

Passif : analyse des fichiers locaux uniquement. Utile en revue de code /
pré-commit pour éviter de committer des clés d'API, tokens, etc.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from ..core.findings import Finding, Severity

NAME = "secrets"

# (nom, regex, sévérité)
PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("Clé privée (PEM)", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("Clé d'accès AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("Token GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("Clé API Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("Token Slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), Severity.HIGH),
    ("Clé secrète Stripe", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), Severity.HIGH),
    ("Token JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), Severity.MEDIUM),
    ("Bearer token dans le code", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"), Severity.MEDIUM),
    ("URL avec identifiants", re.compile(r"[a-z]+://[^/\s:@]+:[^/\s:@]+@[^/\s]+"), Severity.HIGH),
    ("Mot de passe/secret assigné", re.compile(r"""(?i)(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{6,}['"]"""), Severity.MEDIUM),
]

# Extensions/chemins ignorés.
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".mypy_cache", ".idea"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".class", ".jar", ".so", ".pyc"}
MAX_FILE_SIZE = 1_500_000  # 1.5 Mo


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_high_entropy(token: str) -> bool:
    """Heuristique : chaîne longue et à forte entropie (clé probable)."""
    token = token.strip("'\"")
    if len(token) < 20:
        return False
    return _shannon_entropy(token) >= 4.0


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_EXT:
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        yield path


def _redact(match: str) -> str:
    """Masque partiellement une valeur pour ne pas la recopier en clair."""
    if len(match) <= 12:
        return match[:2] + "…" + match[-2:]
    return match[:6] + "…" + match[-4:]


def run(target: str, ctx) -> list[Finding]:
    """`target` est un répertoire local à scanner."""
    log = ctx.logger
    root = Path(target).expanduser().resolve()
    findings: list[Finding] = []

    if not root.exists():
        log.error(f"Chemin introuvable : {root}")
        return findings

    check_entropy = ctx.options.get("secrets_entropy", True)
    entropy_min_len = ctx.options.get("secrets_entropy_min_len", 24)
    log.info(f"Analyse des secrets dans {root}…")
    seen: set[tuple[str, int, str]] = set()

    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(root)
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > 4000:
                continue
            for label, pattern, sev in PATTERNS:
                for m in pattern.finditer(line):
                    val = m.group(0)
                    key = (str(rel), lineno, label)
                    if key in seen:
                        continue
                    seen.add(key)
                    log.warn(f"{label} → {rel}:{lineno}")
                    findings.append(
                        Finding(
                            title=f"Secret potentiel : {label}",
                            severity=sev,
                            target=f"{rel}:{lineno}",
                            module=NAME,
                            description=f"Motif '{label}' détecté dans le code source.",
                            evidence=f"{rel}:{lineno} → {_redact(val)}",
                            recommendation=(
                                "Retirer le secret du code, le révoquer, et utiliser "
                                "un gestionnaire de secrets / variables d'environnement."
                            ),
                            references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                        )
                    )

            # Détection générique par entropie (chaînes longues et aléatoires).
            if check_entropy:
                for token in re.findall(r"""['"]([A-Za-z0-9+/=_\-]{%d,})['"]""" % entropy_min_len, line):
                    if not _looks_high_entropy(token):
                        continue
                    key = (str(rel), lineno, "entropy")
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            title="Chaîne à forte entropie (secret probable)",
                            severity=Severity.LOW,
                            target=f"{rel}:{lineno}",
                            module=NAME,
                            description="Chaîne longue et aléatoire pouvant être une clé/secret.",
                            evidence=f"{rel}:{lineno} → {_redact(token)}",
                            recommendation="Vérifier manuellement ; externaliser si c'est un secret.",
                        )
                    )

    if not findings:
        log.good("Aucun secret évident détecté.")
    return findings
