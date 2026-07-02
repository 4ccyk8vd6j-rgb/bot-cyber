#!/usr/bin/env bash
# Scan rapide « tout-en-un » d'une cible réseau + audit du projet courant.
#
# Usage : ./scripts/quick_scan.sh <cible> [chemin_projet]
# Exemple : ./scripts/quick_scan.sh example.com .
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${1:-}"
PROJECT="${2:-.}"

if [ -z "$TARGET" ]; then
  echo "Usage : $0 <cible> [chemin_projet]" >&2
  exit 1
fi

PY="python3"
if [ -x ".venv/bin/python" ]; then PY=".venv/bin/python"; fi

SCOPE_ARG=()
if [ -f config/scope.json ]; then SCOPE_ARG=(--scope config/scope.json); fi

echo "======================================================"
echo " CyberBot — scan rapide de : $TARGET"
echo "======================================================"

# 1) Analyse réseau (nécessite que la cible soit dans le périmètre).
"$PY" cyberbot.py "${SCOPE_ARG[@]}" scan "$TARGET" || true

# 2) Audit des dépendances du projet local.
"$PY" cyberbot.py deps "$PROJECT" || true

# 3) Recherche de secrets dans le projet local.
"$PY" cyberbot.py secrets "$PROJECT" || true

echo "[+] Rapports disponibles dans ./reports/"
