# Détection d'anomalies (expérimentale)

*English version: [../ml.md](../ml.md)*

## Pourquoi un modèle ?

Les règles ne détectent que ce pour quoi elles ont été écrites. La démo contient une attaque
**lente et discrète** (198.51.100.77 : 31 échecs en 3 heures sur 3 comptes, environ 1 toutes les
5 min) qui reste sous tous les seuils : **aucune règle ne se déclenche**. La question était de
savoir si un modèle non supervisé simple apporte quelque chose dans ce cas. Sur ces données
synthétiques, oui ; c'est la seule affirmation faite.

## Variables (une ligne par IP source et par fenêtre de 60 minutes)

| Variable | Signification |
|---|---|
| `n_events` | événements d'authentification |
| `n_failures` | échecs (y compris comptes inexistants) |
| `n_success` | succès |
| `n_invalid_user` | tentatives sur des comptes inexistants |
| `failure_ratio` | échecs / événements |
| `n_users` | comptes distincts |
| `mean_gap_s` | intervalle moyen entre événements (un seul événement = durée de la fenêtre) |
| `off_hours_ratio` | part des événements hors horaires (même définition que LW-004) |

Les comptages sont transformés par `log1p`. Ni l'IP ni le nom de compte ne sont utilisés comme variables.

## Stratégie d'entraînement

* **Référence (baseline)** : un jeu séparé d'activité normale uniquement (graine 7, 14 jours :
  490 événements, 372 fenêtres), jamais les données de démo. Il joue le rôle d'un « historique
  normal connu ».
* **Ajustement** : `IsolationForest(n_estimators=200, random_state=42)` sur les fenêtres de
  référence **plus** les fenêtres à évaluer. C'est non supervisé : aucune étiquette n'est
  utilisée, donc pas de fuite d'étiquettes.
* **Seuil** : 99e centile des scores des fenêtres *de référence* (`ml.contamination_quantile = 0.01`)
  → environ 1 % des fenêtres normales seraient signalées.
* **Explication** : pour chaque fenêtre, les 3 variables les plus éloignées de la médiane de référence.
* Le modèle est réentraîné à chaque exécution (< 1 s) et jamais écrit sur disque (pas de pickle).

### Un constat à savoir 

La première version entraînait la forêt uniquement sur la référence. Résultat : la force brute à
40 échecs paraissait *moins* anormale que du trafic normal. Une Isolation Forest découpe chaque
variable entre le minimum et le maximum vus à l'entraînement ; une valeur très au-delà tombe dans
la même feuille que le maximum d'entraînement : le modèle **ne sait pas extrapoler**. L'ajuster
sur référence + fenêtres évaluées (seuil toujours calibré sur la seule référence) a corrigé le
problème. Constaté, corrigé, puis verrouillé par un test (`tests/integration/test_pipeline.py`).

## Résultats sur le jeu de démo (réellement mesurés)

Unité = fenêtre (IP source, heure) ; 189 fenêtres ; une fenêtre est « malveillante » si elle
chevauche une attaque étiquetée de cette IP.

| Détecteur | VP | FP | FN | VN | Précision | Rappel |
|---|---|---|---|---|---|---|
| Règles | 4 | 0 | 3 | 182 | 100 % | 57 % |
| Isolation Forest | 6 | 1 | 1 | 181 | 86 % | 86 % |
| Règles + ML | 7 | 1 | 0 | 181 | 88 % | 100 % |

* Les 3 fenêtres manquées par les règles sont l'attaque lente ; le modèle signale les trois.
* Le modèle manque la connexion de `dave` à 03:12 : un seul événement, d'apparence normale ; la
  règle LW-004 la détecte. **Les deux approches sont complémentaires.**
* Le faux positif du modèle est une IP de bruit de fond (1 tentative sur un compte inexistant),
  sans doute un vrai scanner, mais étiquetée bénigne.

## Limites

* **Synthétique et circulaire** : les attaques ont été conçues par la même personne que les
  variables. La précision et le rappel en conditions réelles sont inconnus et seraient certainement plus bas.
* 189 fenêtres dont 7 positives : bien trop peu pour des métriques statistiquement significatives.
* Le seuil est un choix (1 %) ; sur du trafic réel, 1 % de centaines de milliers de fenêtres
  représente beaucoup d'alertes à trier.
* Les anomalies sont présentées comme des **indices de tri, pas des alertes** : sans sévérité ni
  recommandation ; les règles restent la référence.
* La dérive (nouveaux utilisateurs, vacances) imposerait de recalibrer sur une référence récente.

Conserver le modèle est justifié par le cas de l'attaque lente, mais il reste optionnel
(`pip install -e ".[ml]"`, `logwarden demo --no-ml`).
