# Règles de détection

*English version: [../detection-rules.md](../detection-rules.md)*

Tous les paramètres sont dans `src/logwarden/default_config.toml` et peuvent être remplacés avec
`--config mon_fichier.toml`. « Échec » désigne `auth_failure` **ou** `invalid_user`.

## Score de risque

```
score = score de base de la règle
      + 15  si un compte visé est privilégié (root, admin, administrator)
      + 20  si une connexion réussie fait partie des preuves (LW-005 uniquement ; pour LW-003 et
            LW-004, le succès est l'objet même de la règle et déjà compté dans le score de base)
      + 5   par palier de volume atteint : nombre >= 2x, 4x, 8x le seuil de la règle (max +15)
borné entre 0 et 100
```

| Score | Sévérité |
|---|---|
| 0-29 | faible |
| 30-59 | moyenne |
| 60-84 | élevée |
| 85-100 | critique |

Chaque alerte conserve son détail, par ex. `base +70 ; compte privilégié +15 ; volume élevé +5 = 90`.

## LW-001 Force brute

* **Comportement** : nombreux échecs de connexion depuis une même IP en peu de temps.
* **Déclenchement** : ≥ `threshold` (5) échecs depuis la même IP en `window_minutes` (5), borne
  incluse. Une alerte par rafale ; la rafale se termine après `window_minutes` sans échec.
* **Score** : base 40 + compte privilégié + volume (échecs / seuil).
* **Cas limites** : des échecs sur plusieurs comptes restent une force brute (compte vide, liste
  dans l'explication) ; des IP différentes ne sont jamais cumulées (une attaque distribuée est
  manquée, voir les limites) ; les succès ne comptent pas.
* **Tests** : `tests/unit/test_rule_lw001_brute_force.py` (seuil, sous le seuil, borne exacte de la
  fenêtre, regroupement en rafale, deux rafales, séparation par IP, bonus privilégié, paramètres).

## LW-002 Pulvérisation de mots de passe (password spraying)

* **Comportement** : une IP essaie de nombreux comptes (peu d'essais chacun) pour éviter les verrouillages.
* **Déclenchement** : ≥ `distinct_users` (4) comptes distincts en échec depuis la même IP en
  `window_minutes` (10).
* **Score** : base 55 + privilégié (si un compte visé l'est) + volume (comptes / seuil).
* **Cas limites** : 20 échecs sur un seul compte ne sont pas du spraying ; événements sans compte
  ignorés ; un spraying rapide déclenche aussi LW-001 (les deux sont signalés, puis LW-005 les corrèle).
* **Tests** : `test_rule_lw002_password_spray.py`.

## LW-003 Succès après échecs

* **Comportement** : connexion réussie précédée d'échecs répétés depuis la même IP → mot de passe
  probablement deviné.
* **Déclenchement** : succès depuis l'IP X avec ≥ `failures` (3) échecs depuis X (tous comptes)
  dans les `window_minutes` (10) précédentes. Compter tous les comptes couvre le cas « spraying
  puis succès ».
* **Score** : base 70 + privilégié + volume. La prise de contrôle d'un compte privilégié est **critique**.
* **Cas limites** : un utilisateur qui se trompe deux fois puis réussit est normal (seuil 3) ; un
  second succès du même compte et de la même IP dans la fenêtre n'est pas re-signalé ; les échecs
  depuis une autre IP sont ignorés.
* **Tests** : `test_rule_lw003_success_after_failures.py`.

## LW-004 Connexion hors horaires

* **Comportement** : connexion réussie en dehors des heures ouvrées ou le week-end.
* **Déclenchement** : succès dont l'heure locale (`timezone`, UTC par défaut) est hors de
  `[business_start_hour, business_end_hour)` = [7, 20), ou samedi/dimanche si
  `weekends_are_off_hours`. Les comptes de `exempt_users` (ex. `svc_backup`) sont ignorés. Les
  succès d'un même compte, d'une même IP et d'un même jour sont regroupés.
* **Score** : base 25 (faible) + privilégié → moyenne pour root/admin.
* **Cas limites** : 07:00 est ouvré, 20:00 ne l'est pas ; les astreintes provoqueront des faux
  positifs ; le fuseau doit être correct (`Europe/Paris` est pris en charge).
* **Tests** : `test_rule_lw004_off_hours.py` (bornes, week-end, exemption, fuseau, regroupement).

## LW-005 Adresse IP suspecte (corrélation)

* **Comportement** : une IP dont le comportement global dans le jeu de données est suspect.
* **Déclenchement** : l'IP a déclenché ≥ `min_distinct_rules` (2) règles *différentes*, **ou** a
  essayé ≥ `invalid_user_threshold` (3) comptes inexistants (scanners à dictionnaire).
* **Score** : base 50 + privilégié + succès (+20 si une connexion depuis cette IP a réussi) + volume
  (comptes inexistants / seuil).
* **Cas limites** : s'exécute après les autres règles et reçoit leurs alertes ; ignore ses propres
  alertes ; deux alertes de la même règle comptent une seule fois.
* **Tests** : `test_rule_lw005_suspicious_ip.py`.

## Moteur

`detection/__init__.py::run_detection` trie les événements par date, exécute LW-001 à LW-004,
puis les règles de corrélation avec les alertes précédentes, puis trie les alertes par sévérité,
score et date. Les identifiants d'alertes sont déterministes (empreinte de la règle et des
événements) : deux exécutions sur les mêmes données donnent un résultat identique (testé).
