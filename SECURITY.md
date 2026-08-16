# Sécurité de CyberBot

Un outil d'analyse de sécurité manipule, par construction, des données
fournies par des systèmes potentiellement hostiles. Ce document décrit le
modèle de menace retenu, les protections en place et la façon de signaler
une faille.

## Modèle de menace

CyberBot considère comme **non fiables** :

- les réponses HTTP de la cible (corps, en-têtes, redirections) ;
- les bannières de service lues sur un port ouvert ;
- les réponses DNS ;
- les réponses de l'API OSV ;
- les fichiers analysés lors d'un audit local.

L'attaquant supposé est **l'opérateur de la cible analysée**. Son objectif :
faire exécuter à l'analyste une action non voulue (analyser un tiers,
lire un fichier local), falsifier un rapport, ou exécuter du code sur le
poste de l'analyste.

## Protections en place

| Menace | Protection | Test |
| --- | --- | --- |
| La cible redirige le scan vers un hôte hors périmètre (SSRF) | Redirections suivies manuellement, périmètre réévalué à **chaque saut**, maximum 5 sauts | `test_redirect_hors_perimetre_est_refuse` |
| Lecture de fichiers locaux via `file://` | Liste blanche de schémas (`http`, `https`) appliquée à la cible initiale, à chaque redirection et au niveau de la CLI | `test_schemas_non_http_refuses` |
| Lien `javascript:` exécuté au clic dans un rapport | Liste blanche de schémas sur toutes les URL, appliquée dans `Finding` **et** dans le générateur de rapport | `test_rapport_html_ne_contient_aucun_lien_executable` |
| Falsification du terminal ou d'un rapport par séquences ANSI | Assainissement systématique dans `Finding.__post_init__` (point de passage unique) et sur les bannières | `test_finding_assainit_tous_les_champs_externes` |
| Exécution de script depuis un rapport HTML | `Content-Security-Policy: default-src 'none'` + échappement HTML | `test_rapport_html_ne_contient_aucun_lien_executable` |
| Lecture des rapports par un autre utilisateur de la machine | Fichiers créés en `0600`, dossier en `0700` | `test_rapports_lisibles_par_le_seul_proprietaire` |
| Réponse DNS forgée par un tiers | Socket `connect()` (filtrage noyau par source), vérification de l'ID de transaction, du bit QR et de l'écho de la question | `test_dns_rejette_une_question_qui_ne_correspond_pas` |
| Rapport noyé sous un contenu volumineux | Longueur bornée par champ (preuve : 8 000 caractères) | `test_finding_borne_la_taille_des_champs` |
| Réponse DNS malformée (`rdlength` mensonger) | Contrôle de cohérence avant lecture | `test_dns_rejette_un_rdlength_mensonger` |

Ces protections sont couvertes par `tests/test_security.py`. Chaque test
correspond à une faille qui a réellement existé dans le code et a été
démontrée par un PoC avant correction.

## Le périmètre : garde-fou principal

Le contrôle de périmètre (`config/scope.json`) est ce qui distingue cet
outil d'un outil offensif. Il est **actif par défaut** et restreint à
`localhost` en l'absence de configuration.

Points d'attention :

- `--allow-any` désactive complètement ce contrôle. À réserver aux actifs
  dont vous êtes responsable.
- Le périmètre est vérifié avant chaque module actif **et** à chaque
  redirection HTTP.
- Les modules passifs (`deps`, `secrets`, `cve`, `dns`) n'envoient aucune
  requête à la cible et ne sont donc pas soumis au périmètre.

## Limites connues

Ces points sont assumés et documentés plutôt que corrigés en silence :

- **Rebinding DNS.** Le périmètre résout le nom au moment du contrôle ; un
  serveur DNS hostile pourrait renvoyer une adresse différente au moment de
  la connexion. Une protection complète imposerait d'épingler l'adresse
  résolue jusqu'à la connexion, ce que la bibliothèque standard ne permet
  pas simplement.
- **Pas de validation DNSSEC.** Le client DNS interne vérifie la cohérence
  des réponses mais ne valide pas les signatures.
- **`--allow-any` est un contournement volontaire.** Aucun garde-fou ne
  subsiste lorsqu'il est utilisé, par conception.
- **Les rapports contiennent des informations sensibles.** Ils sont exclus
  du dépôt via `.gitignore` et créés en `0600`, mais leur diffusion reste
  sous votre responsabilité.

## Signaler une vulnérabilité

Ouvrez une issue décrivant :

1. le composant concerné ;
2. un scénario reproductible (idéalement un test qui échoue) ;
3. l'impact envisagé.

N'incluez jamais de données réelles issues d'un système tiers.

## Usage légal

L'analyse de systèmes sans autorisation écrite est illégale dans la plupart
des juridictions. N'utilisez CyberBot que sur des actifs qui vous
appartiennent ou dans le cadre d'un mandat explicite.
