# Portfolio LogWarden — préparation à l’entretien

Ce document est ma préparation personnelle pour présenter LogWarden lors d’un entretien.  
Il résume ce que j’ai construit, ce que j’ai appris, les difficultés rencontrées et la manière  
dont je souhaite présenter le projet de façon honnête.

## 1. Présentation en 60 secondes

> « LogWarden est un mini-moteur de détection inspiré d’un SOC, écrit en Python.  
> Il analyse des journaux d’authentification SSH et des journaux d’une application web,  
> puis les normalise dans un format d’événement commun.  
>
> Ensuite, il applique six règles explicables : force brute, password spraying, succès après  
> échecs, connexion hors horaires, corrélation par IP et attaque distribuée visant un même  
> compte depuis plusieurs adresses IP.  
>
> Chaque alerte reçoit un score de risque compris entre 0 et 100, une explication en français  
> ou en anglais, ainsi qu’une action recommandée. Les événements et les alertes sont stockés  
> dans SQLite. Le projet génère aussi un rapport Markdown et propose un tableau de bord local  
> avec Streamlit.  
>
> J’ai ajouté une Isolation Forest pour détecter un cas particulier : une attaque lente qui  
> reste sous les seuils des règles. Je l’ai évaluée sur des données synthétiques uniquement,  
> et je présente les résultats comme expérimentaux.  
>
> Le projet contient 419 tests automatisés, incluant des tests de sécurité sur des entrées  
> potentiellement hostiles. »

## 2. Démonstration de cinq minutes

| Temps | Action | Message clé |
|---|---|---|
| 0:00 | Lancer `logwarden demo --lang fr` | Le projet est reproductible avec une seule commande et une graine fixe. |
| 0:45 | Montrer la sortie : 865 lignes, 4 lignes mal formées, 1 doublon | Les erreurs sont comptées et signalées, jamais ignorées silencieusement. |
| 1:15 | Lancer `logwarden dashboard --lang fr`, puis ouvrir « Vue d’ensemble » | Le tableau de bord montre 9 alertes, dont 6 élevées ou critiques, sans alerte sur le trafic normal. |
| 2:00 | Ouvrir l’onglet « Alertes » et montrer une alerte critique LW-003 | Je peux expliquer le score, les événements de preuve, l’explication et l’action recommandée. |
| 3:00 | Basculer l’interface en anglais | L’internationalisation a été pensée dès le début, avec des clés de traduction et des paramètres en base. |
| 3:30 | Ouvrir l’onglet « Anomalies » | L’Isolation Forest détecte une attaque lente que les règles seules ne repèrent pas. |
| 4:15 | Ouvrir `tests/unit/test_rule_lw001_brute_force.py`, puis lancer `pytest -q` | Les tests couvrent les cas normaux, les cas limites et les entrées malveillantes. |
| 4:45 | Conclure sur les limites | Données synthétiques, deux formats de logs, règles principalement fondées sur l’IP et modèle ML expérimental. |

Je prépare aussi un plan B : les captures d’écran présentes dans `docs/images/`, au cas où  
l’ordinateur ou le tableau de bord poserait problème pendant la démonstration.

## 3. Compétences réellement mobilisées

### Cybersécurité défensive

J’ai travaillé sur des techniques d’attaque courantes contre l’authentification : force brute,  
password spraying, tentatives de mots de passe, scans de comptes et attaques distribuées.  
J’ai ensuite traduit ces comportements en règles de détection, en score de risque et en alertes  
compréhensibles.

J’ai aussi réfléchi à la réduction du bruit : regrouper une rafale d’échecs en une seule alerte,  
graduer la sévérité et éviter d’alerter sur chaque événement isolé.

Enfin, j’ai traité les logs comme des données potentiellement hostiles. Un attaquant peut  
contrôler certains champs, par exemple un nom d’utilisateur ou une adresse IP. J’ai donc prévu  
des protections contre les injections SQL, les séquences d’échappement de terminal, les injections  
Markdown ou CSV, ainsi que le masquage de secrets éventuels.

### Analyse de journaux

J’ai appris à manipuler des logs syslog/OpenSSH, où l’année n’est pas toujours présente et où  
les fuseaux horaires peuvent poser problème. J’ai également travaillé avec des logs JSON Lines.

Le projet normalise ces formats vers un modèle d’événement commun, détecte les lignes mal  
formées et dédoublonne les événements grâce à une empreinte.

### Python

J’ai utilisé une structure de paquet installable avec `pyproject.toml` et un dossier `src/`.  
Le code utilise notamment des dataclasses, des enums, des expressions régulières, `argparse`,  
`sqlite3`, `tomllib`, `zoneinfo` et du typage.

### Bases de données

J’ai conçu un schéma relationnel avec SQLite, utilisé des transactions, des requêtes paramétrées  
et une table de liaison. La base est ouverte en lecture seule pour le tableau de bord, et  
l’importation est idempotente.

### Tests et QA

J’ai écrit des tests unitaires, des tests d’intégration et des tests d’interface avec pytest.  
J’ai utilisé des fixtures, des tests paramétrés et des cas limites.

J’ai aussi réalisé un test de mutation manuel : j’ai introduit volontairement une erreur dans une  
règle pour vérifier qu’un test échouait réellement. Cela m’a permis de valider l’utilité de mes tests.

### DevOps

J’ai utilisé un environnement virtuel, un fichier de verrouillage, un Makefile, Ruff pour le  
lint et le formatage, ainsi qu’un workflow GitHub Actions. L’objectif était de rendre le projet  
reproductible et facile à maintenir.

### Data et machine learning

J’ai ajouté une Isolation Forest pour détecter une attaque lente. J’ai travaillé sur  
l’ingénierie de variables, le choix du seuil, la précision et le rappel.

Surtout, j’ai appris à être prudent avec les résultats : mes données sont synthétiques, donc  
les chiffres valident la logique du système, mais ne prouvent pas une performance réelle en  
production.

### Systèmes et réseaux

Le projet m’a permis de mieux comprendre `auth.log`, `sshd`, PAM, cron, les fuseaux horaires,  
les adresses IPv4 et IPv6, ainsi que la différence entre une écoute sur `127.0.0.1` et `0.0.0.0`.

## 4. Difficultés rencontrées et ce qu’elles m’ont appris

### L’Isolation Forest ne sait pas extrapoler

Au début, j’ai entraîné le modèle uniquement sur les données de référence. Il considérait alors  
une force brute de 40 échecs comme moins anormale que du trafic normal.

J’ai compris que les arbres de l’Isolation Forest coupent principalement entre les valeurs minimales  
et maximales observées pendant l’entraînement. J’ai donc ajusté l’approche en utilisant la référence  
et les données évaluées pour l’entraînement, tout en calibrant le seuil sur la référence seule.

Cela m’a appris à diagnostiquer un modèle au lieu de lui faire confiance aveuglément.

### Conflit de nom de paramètre

J’ai rencontré une `TypeError` avec `ConfigError("...", key=...)`, car le constructeur possédait  
déjà un argument nommé `key`. Les tests de configuration ont révélé le problème.

Je l’ai corrigé avec un argument positionnel uniquement, en utilisant `/`. Cela m’a montré que les  
tests des chemins d’erreur permettent de trouver de vrais bugs.

### Faux échec causé par le cache Python

Après un test de mutation, Python a réutilisé le bytecode présent dans `__pycache__`. Le fichier  
restauré avait la même taille et la même seconde de modification, donc Python n’a pas recompilé  
le module.

J’ai appris à comprendre l’outillage avant de conclure que le problème venait du code.

### Les logs syslog n’ont pas d’année

Il faut fournir l’année et gérer correctement le passage de décembre à janvier. J’ai aussi dû  
vérifier qu’une ligne invalide, comme « Feb 30 », ne modifie pas l’état du parseur.

### Les logs peuvent être contrôlés par un attaquant

Un nom d’utilisateur peut contenir une séquence d’échappement terminal, une image Markdown ou une  
formule de tableur. J’ai donc protégé chaque type de sortie et ajouté des tests correspondants.

## 5. Questions probables en entretien

### Pourquoi des règles plutôt que du machine learning ?

Les règles sont explicables, testables et auditables. Un analyste peut comprendre pourquoi une  
alerte a été déclenchée.

Le machine learning est utilisé seulement lorsqu’il apporte une valeur supplémentaire. Ici,  
l’Isolation Forest aide à repérer une attaque lente qui reste sous les seuils des règles.

### Comment réduis-tu les faux positifs ?

J’utilise des seuils configurables, un regroupement des événements en rafales, une exemption des  
comptes de service et une sévérité graduée. Pour LW-003, j’ai choisi un seuil de trois échecs,  
car deux erreurs de mot de passe peuvent être normales.

Une amélioration possible serait de créer des profils par utilisateur afin de réduire encore les  
faux positifs.

### Quelle est la différence entre force brute et password spraying ?

La force brute consiste à essayer beaucoup de mots de passe sur un même compte. Le password  
spraying consiste à essayer peu de mots de passe sur beaucoup de comptes, afin d’éviter le  
verrouillage du compte.

C’est pourquoi j’ai deux règles distinctes : l’une regarde le nombre d’échecs sur un compte,  
l’autre le nombre de comptes ciblés depuis une même source.

### Que se passe-t-il si un attaquant utilise 1 000 adresses IP ?

La règle LW-006 détecte une attaque distribuée lorsqu’un même compte est ciblé par un grand nombre  
d’adresses IP distinctes. Elle complète les règles fondées sur l’IP, qui restent utiles pour  
repérer les attaques concentrées sur une seule source.

### Comment as-tu évalué le modèle ? Les chiffres sont-ils fiables ?

J’ai évalué le modèle sur une vérité terrain synthétique, séparée des données utilisées pour  
l’analyse. Les résultats valident la logique du système, mais ne représentent pas une performance  
réelle en production.

Le jeu de données est petit et les attaques ont été conçues par moi. Je le dis explicitement dans  
la documentation et dans le rapport.

### Comment l’outil lui-même est-il sécurisé ?

Je considère les logs comme des entrées hostiles. J’utilise des requêtes SQL paramétrées, je  
nettoie les caractères de contrôle, j’échappe le Markdown, je protège les sorties CSV et je masque  
les secrets potentiels.

Le tableau de bord est en lecture seule et écoute sur localhost. Le projet n’utilise pas `pickle`.

### Pourquoi SQLite plutôt qu’Elasticsearch ou PostgreSQL ?

Pour ce projet, le volume de données est faible et l’objectif est la reproductibilité locale.  
SQLite ne demande aucune installation supplémentaire.

Dans un environnement réel, j’utiliserais plutôt un SIEM comme Elasticsearch, Splunk ou Wazuh.  
LogWarden illustre la logique de détection, mais ne remplace pas ces outils.

### Comment ajouterais-tu une nouvelle source de logs ?

J’ajouterais un parseur qui implémente une fonction du type :

```python
parse_line() -> Event | Skip | Malformed
```

Puis j’ajouterais les tests correspondants. Les règles travaillent sur le format normalisé, donc  
elles n’ont pas besoin d’être modifiées pour chaque nouvelle source.

### Qu’as-tu testé et comment sais-tu que tes tests sont utiles ?

J’ai testé les cas positifs, négatifs et limites de chaque règle. J’ai aussi testé les entrées  
mal formées, les erreurs de stockage et l’interface.

Pour vérifier l’utilité des tests, j’ai introduit volontairement un bug, par exemple une fenêtre  
exclusive au lieu d’une fenêtre inclusive, afin de m’assurer qu’un test échouait.

### Que ferais-tu différemment ?

Je commencerais directement par une règle de détection par compte visé, afin de couvrir plus tôt  
les attaques distribuées. J’essaierais aussi d’évaluer le système sur un jeu de données public  
étiqueté, si sa licence le permet.

## 6. Formulations honnêtes

### CV — version courte

> LogWarden — outil Python de détection d’intrusions sur journaux d’authentification (SSH, web) :  
> 6 règles explicables, dont détection d’attaques distribuées, score de risque, SQLite, tableau de  
> bord Streamlit bilingue et Isolation Forest expérimentale ; 419 tests pytest et CI GitHub Actions.  
> Projet personnel, données synthétiques.

### CV — version détaillée

* Conçu un moteur de détection par règles pour journaux d’authentification : force brute, password  
  spraying, succès après échecs, connexions hors horaires, corrélation par IP et attaque distribuée  
  (LW-006), avec score de risque explicable et alertes bilingues.
* Développé l’importation et la normalisation de journaux OpenSSH et JSON, robuste aux entrées mal  
  formées et malveillantes : injections SQL, terminal et CSV, masquage de secrets et validation des entrées.
* Mis en place 419 tests automatisés — unitaires, intégration et interface —, une CI multi-versions  
  et une évaluation honnête d’un modèle Isolation Forest en complément des règles de détection.

### LinkedIn

> J’ai construit LogWarden, un petit outil de détection inspiré d’un SOC, pour mieux comprendre le  
> métier d’analyste Blue Team.  
>
> Il analyse des journaux SSH et d’une application web, détecte six comportements suspects avec des  
> règles explicables, attribue un score de risque et explique chaque alerte en français ou en anglais.  
>
> Les règles couvrent notamment la force brute, le password spraying, les succès après échecs, les  
> connexions hors horaires, la corrélation par IP et les attaques distribuées visant un même compte  
> depuis plusieurs adresses IP.  
>
> Ce que j’en retiens : un modèle de machine learning ne remplace pas des règles claires. Sur mes  
> données, l’Isolation Forest détecte une attaque lente que les règles manquent, mais rate une  
> connexion nocturne isolée que les règles voient. Les deux approches sont complémentaires.  
>
> Données 100 % synthétiques, résultats non représentatifs d’un environnement réel.  
> Code et documentation : [lien GitHub].  
>
> #cybersécurité #blueteam #python #SOC

### À éviter

Je évite de dire :

- « IA de détection d’intrusions » ;
- « précision de 100 % » ;
- « utilisé en production » ;
- « SIEM ».

Je préfère dire :

- « projet personnel » ;
- « données synthétiques » ;
- « modèle expérimental » ;
- « mini-moteur de détection inspiré d’un SOC ».

## 7. Adapter le discours selon le poste

### Cybersécurité / SOC

Je mets en avant :

- les règles de détection ;
- la corrélation d’événements ;
- la gestion des faux positifs ;
- le modèle de menace ;
- les actions recommandées après une alerte.

### QA / DevOps

Je mets en avant :

- les 419 tests ;
- les cas limites ;
- le test de mutation ;
- la matrice de versions Python ;
- le fichier de verrouillage ;
- la CI GitHub Actions ;
- la reproductibilité et le Makefile.

### Systèmes et réseaux

Je mets en avant :

- `auth.log`, `sshd` et PAM ;
- les fuseaux horaires ;
- les adresses IPv4 et IPv6 ;
- l’écoute locale ;
- fail2ban comme réponse opérationnelle possible.

## 8. Utilisation de l’IA

J’ai utilisé un assistant IA pour m’aider à déboguer certaines parties du projet et à améliorer  
la documentation. J’ai toutefois conçu la structure du projet, revu les règles de détection,  
lancé les tests, analysé les résultats et validé les choix techniques moi-même.

Je considère l’IA comme un outil d’apprentissage et de productivité, pas comme un remplaçant de  
ma compréhension technique.