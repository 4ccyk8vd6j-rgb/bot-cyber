# 🛡️ CyberBot

**Bot d'analyse de sécurité défensive, clé en main.** Reconnaissance réseau,
audit d'en-têtes HTTP, contrôle TLS, audit de dépendances (OSV), détection de
secrets et recherche de CVE — le tout dans un seul outil en ligne de commande,
**sans aucune dépendance externe** (bibliothèque standard Python uniquement).

> ⚠️ **Usage autorisé uniquement.** N'analysez que des systèmes qui vous
> appartiennent ou pour lesquels vous disposez d'une **autorisation écrite
> explicite** (contrat de pentest, programme de bug bounty *in-scope*, CTF,
> labo personnel). Un contrôle de périmètre (*scope*) est intégré et **actif
> par défaut** pour vous éviter de cibler par erreur des hôtes non autorisés.
> L'utilisation contre des systèmes sans autorisation est illégale.

---

## ✨ Fonctionnalités

| Module | Type | Description |
| --- | --- | --- |
| `recon` | actif | Résolution DNS + scan de ports courants (connect TCP) + bannières |
| `headers` (`web`) | actif | En-têtes de sécurité HTTP manquants, divulgation d'info, attributs de cookies |
| `tls` | actif | Version TLS négociée, protocoles obsolètes, validité/expiration du certificat |
| `deps` | passif | Audit des dépendances (`requirements.txt`, `package-lock.json`) via l'API OSV |
| `secrets` | passif | Détection de secrets codés en dur (clés API, tokens, clés privées, entropie) |
| `cve` | passif | Recherche de vulnérabilités connues (CVE/GHSA) via OSV |

- **Modules actifs** : touchent une cible réseau distante → **soumis au contrôle de périmètre**.
- **Modules passifs** : n'analysent que des fichiers/données locaux → pas de périmètre requis.
- **Rapports** générés automatiquement en **JSON, Markdown et HTML**.
- **Code de sortie** `1` si au moins un finding *High/Critical* → intégrable en CI.

---

## 🚀 Installation

Aucune dépendance n'est nécessaire pour l'usage de base (Python ≥ 3.9).

```bash
git clone <repo>
cd bot-cyber

# Option A — utilisation directe
python3 cyberbot.py --help

# Option B — installation (crée la commande `cyberbot` + venv + config)
./scripts/setup.sh
source .venv/bin/activate
cyberbot --help
```

---

## 🎯 Définir votre périmètre (obligatoire pour les scans actifs)

Copiez l'exemple et n'y mettez **que** des cibles autorisées :

```bash
cp config/scope.example.json config/scope.json
```

```json
{
  "domains": ["example.com"],
  "hosts": ["localhost", "127.0.0.1"],
  "cidrs": ["127.0.0.0/8", "10.0.0.0/24"],
  "allow_private": false
}
```

- `domains` : autorise le domaine **et ses sous-domaines**.
- `hosts` : hôtes/IP exacts.
- `cidrs` : plages réseau autorisées.
- `allow_private` : autorise les IP privées/loopback (pratique en labo).

Si aucun fichier n'est fourni, le périmètre par défaut est **restreint à
`localhost`**. Le drapeau `--allow-any` désactive le contrôle (à réserver
strictement à vos propres actifs).

---

## 📖 Utilisation

```bash
# Analyse complète d'un hôte (recon + headers + tls)
cyberbot scan example.com --scope config/scope.json

# En-têtes de sécurité HTTP
cyberbot web https://example.com

# Configuration TLS / certificat
cyberbot tls example.com:443

# Reconnaissance (DNS + ports)
cyberbot recon 10.0.0.5

# Audit des dépendances d'un projet local (OSV)
cyberbot deps ./mon-projet

# Recherche de secrets codés en dur
cyberbot secrets ./mon-projet

# Recherche de CVE
cyberbot cve PyPI:requests:2.19.0
cyberbot cve CVE-2021-44228
```

Options globales utiles : `-v/--verbose`, `--no-banner`, `--no-report`,
`--report-dir DOSSIER`, `--scope FICHIER`.

### Scan rapide tout-en-un

```bash
./scripts/quick_scan.sh example.com ./mon-projet
```

---

## 📊 Rapports

Chaque exécution produit trois fichiers dans `reports/` (horodatés) :

- `*.json` — exploitable par des outils/CI ;
- `*.md` — lisible dans un ticket / une PR ;
- `*.html` — rapport présentable (clair/sombre, code couleur par sévérité).

Les rapports sont ignorés par git (`.gitignore`) car ils peuvent contenir des
informations sensibles.

---

## 🧪 Tests

```bash
python3 -m pytest -q
```

---

## 🏗️ Architecture

```
bot-cyber/
├── cyberbot.py              # point d'entrée pratique
├── cyberbot/
│   ├── cli.py               # CLI (argparse) + orchestration
│   ├── core/
│   │   ├── scope.py         # contrôle de périmètre (garde-fou éthique/légal)
│   │   ├── findings.py      # modèle Finding + sévérités
│   │   └── reporter.py      # rapports JSON / Markdown / HTML
│   ├── modules/             # un module = une capacité d'analyse
│   │   ├── recon.py  web_headers.py  tls_check.py
│   │   ├── deps_audit.py  secrets_scan.py  cve_lookup.py
│   └── utils/               # net (urllib/socket/ssl) + logging
├── config/scope.example.json
├── scripts/                 # setup.sh, quick_scan.sh
└── tests/                   # suite pytest
```

### Ajouter un module

Créez `cyberbot/modules/mon_module.py` exposant :

```python
NAME = "mon_module"

def run(target: str, ctx) -> list[Finding]:
    ...
```

puis enregistrez-le dans `cyberbot/modules/__init__.py` (`REGISTRY` +
`ACTIVE_MODULES`/`PASSIVE_MODULES`).

---

## ⚖️ Éthique & responsabilité

Cet outil est **volontairement défensif** : il n'inclut ni exploitation, ni
déni de service, ni contournement de protections, ni ciblage de masse. Il
n'automatise que des vérifications de configuration et de vulnérabilités
connues. Vous êtes seul responsable du respect des lois applicables et de
l'obtention des autorisations nécessaires avant toute analyse.

## 📄 Licence

MIT — voir [LICENSE](LICENSE).
