"""Permet d'exécuter le paquet via `python -m cyberbot`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
