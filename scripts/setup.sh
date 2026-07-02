#!/usr/bin/env bash
# Installe CyberBot en mode développement dans un venv.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[*] Création de l'environnement virtuel…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Mise à jour de pip…"
pip install --upgrade pip >/dev/null

echo "[*] Installation de CyberBot (+ outils de dev)…"
pip install -e ".[dev]"

if [ ! -f config/scope.json ]; then
  cp config/scope.example.json config/scope.json
  echo "[+] config/scope.json créé depuis l'exemple. ÉDITEZ-LE avant tout scan actif."
fi

echo "[+] Terminé. Activez avec : source .venv/bin/activate"
echo "    Puis : cyberbot --help"
