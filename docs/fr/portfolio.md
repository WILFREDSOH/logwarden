# LogWarden — préparation portfolio et entretiens

Ce document t'aide à présenter LogWarden honnêtement. Règle d'or : **ne revendique que ce que tu
sais expliquer et refaire**. Avant un entretien, relis le code des règles, lance `logwarden demo`
et les tests, et entraîne-toi à modifier un seuil en direct.

## 1. Présentation technique en 60 secondes

> « LogWarden est un mini-moteur de détection inspiré d'un SOC, écrit en Python. Il importe des
> journaux SSH et d'une application web, les normalise dans un format d'événement commun, puis
> applique cinq règles explicables : force brute, password spraying, succès après échecs,
> connexion hors horaires et corrélation par IP. Chaque alerte reçoit un score de 0 à 100 dont le
> calcul est détaillé, une explication en français ou en anglais et une action recommandée. Tout
> est stocké dans SQLite, avec un rapport Markdown et un tableau de bord Streamlit local. J'ai
> ajouté une Isolation Forest pour un cas précis, une attaque lente sous les seuils, et je l'ai
> évaluée honnêtement : sur données synthétiques uniquement. Le projet a 379 tests automatisés,
> dont des tests de sécurité sur les entrées hostiles. »

## 2. Démonstration de 5 minutes

| Temps | Action | Message clé |
|---|---|---|
| 0:00 | `logwarden demo --lang fr` | une seule commande, résultat reproductible (graine fixe) |
| 0:45 | Montrer la sortie : 865 lignes, 4 mal formées, 1 doublon | les erreurs sont comptées, jamais ignorées |
| 1:15 | `logwarden dashboard --lang fr` → Vue d'ensemble | 9 alertes, 6 élevées/critiques, aucune sur le trafic normal |
| 2:00 | Onglet Alertes → alerte critique LW-003 | explication, détail du score 70+15+5, événements de preuve, action |
| 3:00 | Basculer en anglais dans la barre latérale | i18n pensée dès le départ (clé + paramètres en base) |
| 3:30 | Onglet Anomalies (ML) | l'attaque lente : aucune règle, 3 fenêtres signalées par le modèle ; « règles + ML » complémentaires |
| 4:15 | Ouvrir `tests/unit/test_rule_lw001_brute_force.py` puis `pytest -q` | tests de bornes (fenêtre inclusive), 379 tests en ~17 s |
| 4:45 | Conclure sur les limites | données synthétiques, règles par IP, 2 formats |

Prépare un plan B : les captures de `docs/images/` si l'ordinateur pose problème.

## 3. Compétences réellement mobilisées

* **Cybersécurité défensive** : techniques d'attaque sur l'authentification (force brute,
  spraying, credential guessing, scans de comptes), logique de détection et de corrélation,
  hiérarchisation des alertes, réduction du bruit (une alerte par rafale), modèle de menace de
  l'outil lui-même (injections SQL, terminal, Markdown, CSV, secrets dans les logs).
* **Analyse de journaux** : format syslog/OpenSSH, absence d'année et fuseaux horaires, JSON Lines,
  normalisation, dédoublonnage par empreinte.
* **Python** : paquet installable (`pyproject.toml`, disposition `src/`), dataclasses, enums,
  expressions régulières, `argparse`, `sqlite3`, `tomllib`, `zoneinfo`, typage.
* **Bases de données** : schéma relationnel, table de liaison, transactions, requêtes paramétrées,
  mode lecture seule, idempotence.
* **Tests / QA** : pytest, fixtures, tests paramétrés, cas limites, tests d'intégration,
  test d'interface sans navigateur, test de mutation manuel, matrice de versions Python.
* **DevOps** : environnements virtuels, fichier de verrouillage, Makefile, lint/format `ruff`,
  workflow GitHub Actions, historique Git en commits cohérents.
* **Data / ML** : ingénierie de variables, Isolation Forest, calibration d'un seuil, précision/rappel,
  biais d'une évaluation synthétique.
* **Systèmes et réseaux** : `auth.log`, sshd, PAM, cron, plages d'adresses de documentation
  RFC 5737, IPv4/IPv6, écoute sur `127.0.0.1` vs `0.0.0.0`.

## 4. Difficultés techniques rencontrées (et ce qu'elles t'apprennent)

1. **L'Isolation Forest ne sait pas extrapoler.** Entraînée sur la seule référence, elle trouvait
   une force brute de 40 échecs moins anormale que du trafic normal. Cause : les arbres coupent
   entre le min et le max vus à l'entraînement. Solution : ajuster sur référence + données
   évaluées, seuil calibré sur la référence seule. → savoir diagnostiquer un modèle au lieu de le croire.
2. **Conflit de nom de paramètre.** `ConfigError("...", key=...)` levait une `TypeError` car le
   constructeur avait déjà un argument `key`. Révélé par les tests de configuration ; corrigé par
   un argument *positional-only* (`/`). → les tests de chemins d'erreur trouvent de vrais bugs.
3. **Faux échec dû au cache Python.** Après un test de mutation, Python a réutilisé le bytecode
   (`__pycache__`) de la version modifiée, car le fichier restauré avait la même taille et la même
   seconde de modification. → comprendre l'outillage avant d'accuser le code.
4. **Syslog n'a pas d'année.** Il faut la fournir et gérer le passage décembre→janvier, sans
   qu'une ligne invalide (« Feb 30 ») modifie l'état du parseur.
5. **Données de logs contrôlées par l'attaquant.** Un nom d'utilisateur peut contenir une séquence
   d'échappement terminal, une image Markdown ou une formule de tableur : chaque sortie a sa
   protection et son test.

## 5. Questions probables en entretien

**Pourquoi des règles plutôt que du machine learning ?**
Les règles sont explicables, testables et auditables : un analyste sait pourquoi l'alerte existe.
Le ML est ajouté seulement là où il apporte quelque chose (attaque lente), comme signal secondaire.

**Comment réduis-tu les faux positifs ?**
Seuils configurables, regroupement en rafales, exemption des comptes de service, seuil de 3 échecs
pour LW-003 (deux fautes de frappe sont normales), sévérité graduée. Pistes : profils par utilisateur.

**Quelle est la différence entre force brute et password spraying ?**
Force brute : beaucoup d'essais sur un compte. Spraying : peu d'essais sur beaucoup de comptes,
pour éviter le verrouillage. D'où deux règles : nombre d'échecs vs nombre de comptes distincts.

**Que se passe-t-il si un attaquant utilise 1 000 IP ?**
Les règles par IP ne le voient pas : c'est une limite documentée. Il faudrait une règle par compte
visé (nombre d'IP distinctes échouant sur un même compte).

**Comment as-tu évalué le modèle ? Les chiffres sont-ils fiables ?**
Sur une vérité terrain synthétique séparée des données. Les chiffres valident la logique, pas la
performance réelle : jeu petit, attaques conçues par moi. Je le dis explicitement dans le rapport.

**Comment est sécurisé l'outil lui-même ?**
Les logs sont traités comme hostiles : requêtes paramétrées, nettoyage des caractères de contrôle,
échappement Markdown, protection CSV, masquage des secrets, limites de taille, tableau de bord en
lecture seule sur localhost, pas de pickle.

**Pourquoi SQLite et pas Elasticsearch ou PostgreSQL ?**
Volume faible, zéro installation, reproductible. Pour la production : un SIEM (Elastic, Splunk,
Wazuh) ; LogWarden illustre la logique de détection, il ne les remplace pas.

**Comment ajouterais-tu une nouvelle source (nginx, Windows) ?**
Un parseur qui implémente `parse_line() -> Event | Skip | Malformed`, ses tests, et c'est tout :
les règles travaillent sur le format normalisé.

**Qu'as-tu testé et comment sais-tu que tes tests sont utiles ?**
Cas positifs, négatifs et bornes de chaque règle ; entrées mal formées ; erreurs de stockage ;
interface. J'ai introduit volontairement un bug (fenêtre exclusive) pour vérifier qu'un test échoue.

**Qu'est-ce que tu ferais différemment ?**
Commencer par une règle par compte visé, et évaluer sur un jeu public étiqueté dont la licence le permet.

## 6. Formulations honnêtes

**CV (une ligne)**
> LogWarden — outil Python de détection d'intrusions sur journaux d'authentification (SSH, web) :
> 5 règles explicables avec score de risque, SQLite, tableau de bord Streamlit bilingue,
> Isolation Forest expérimentale ; 379 tests pytest, CI GitHub Actions. Projet personnel, données synthétiques.

**CV (version détaillée, 3 puces)**
* Conçu un moteur de détection par règles (force brute, password spraying, succès après échecs,
  hors horaires, corrélation par IP) avec score de risque explicable et alertes bilingues.
* Développé l'importation et la normalisation de journaux OpenSSH et JSON, robuste aux entrées
  mal formées et malveillantes (injections SQL/terminal/CSV, masquage de secrets).
* Mis en place 379 tests automatisés (unitaires, intégration, interface), une CI multi-versions et
  une évaluation honnête d'un modèle Isolation Forest face aux règles.

**LinkedIn (publication)**
> J'ai construit LogWarden, un petit outil de détection inspiré d'un SOC pour mieux comprendre le
> métier d'analyste Blue Team. Il analyse des journaux SSH et d'une application web, détecte cinq
> comportements suspects avec des règles explicables, attribue un score de risque et explique
> chaque alerte en français ou en anglais.
> Ce que j'en retiens : un modèle de ML ne remplace pas des règles claires — sur mes données, il
> détecte une attaque lente que les règles manquent, mais rate une connexion nocturne isolée que
> les règles voient. Les deux sont complémentaires.
> Données 100 % synthétiques, résultats non représentatifs d'un environnement réel. Code et
> documentation : [lien GitHub]. #cybersécurité #blueteam #python #SOC

**À éviter** : « IA de détection d'intrusions », « précision de 100 % », « utilisé en production »,
« SIEM ». Préfère « projet personnel », « données synthétiques », « expérimental ».

## 7. Adapter selon le poste visé

* **Cybersécurité / SOC** : insister sur les règles, la corrélation, les faux positifs, le modèle
  de menace, les recommandations d'action.
* **QA / DevOps** : 379 tests, cas limites, test de mutation, matrice Python 3.11-3.13, lockfile,
  CI, reproductibilité, Makefile.
* **Systèmes et réseaux** : syslog, sshd/PAM, fuseaux horaires, adresses IPv4/IPv6, écoute locale,
  fail2ban comme réponse opérationnelle.
