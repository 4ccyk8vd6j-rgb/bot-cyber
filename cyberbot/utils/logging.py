"""Journalisation console simple avec couleurs ANSI."""

from __future__ import annotations

import sys

_COLORS = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}


def _supports_color() -> bool:
    return sys.stdout.isatty()


class Logger:
    def __init__(self, verbose: bool = False, use_color: bool | None = None) -> None:
        self.verbose = verbose
        self.color = _supports_color() if use_color is None else use_color

    def _c(self, text: str, color: str) -> str:
        if not self.color:
            return text
        return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"

    def info(self, msg: str) -> None:
        print(f"{self._c('[*]', 'cyan')} {msg}")

    def good(self, msg: str) -> None:
        print(f"{self._c('[+]', 'green')} {msg}")

    def warn(self, msg: str) -> None:
        print(f"{self._c('[!]', 'yellow')} {msg}")

    def error(self, msg: str) -> None:
        print(f"{self._c('[x]', 'red')} {msg}", file=sys.stderr)

    def debug(self, msg: str) -> None:
        if self.verbose:
            print(f"{self._c('[d]', 'dim')} {self._c(msg, 'dim')}")

    def section(self, title: str) -> None:
        print()
        print(self._c(f"══ {title} ", "bold") + self._c("═" * max(0, 40 - len(title)), "dim"))
