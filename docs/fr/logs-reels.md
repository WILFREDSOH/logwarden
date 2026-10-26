# Validation sur de vrais journaux SSH publics

*English version: [../real-logs.md](../real-logs.md)*

## Jeu de données

* **Source** : Loghub, `OpenSSH_2k.log`, https://github.com/logpai/loghub
  (Zhu et al., *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*,
  ISSRE 2023). Utilisation libre pour la recherche et l'enseignement, en citant le dépôt.
* 2 000 lignes d'un vrai serveur OpenSSH exposé sur Internet (décembre, année non enregistrée).
* Le fichier n'est **pas redistribué** dans ce dépôt (`data/external/` est ignoré par Git).

## Reproduire

    mkdir -p data/external
    curl -sS -o data/external/OpenSSH_2k.log \
      https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log
    logwarden ingest data/external/OpenSSH_2k.log --db data/external/loghub.db --year 2015
    logwarden detect --db data/external/loghub.db
    logwarden dashboard --db data/external/loghub.db --lang fr

## Résultats (mesurés)

| Indicateur | Valeur |
|---|---|
| Lignes lues | 2 000 |
| Événements d'authentification | 519 (383 échecs, 135 tentatives sur des comptes inexistants, 1 succès) |
| Lignes mal formées | 0 |
| Alertes | 22 (18 élevées, 4 moyennes) |
| Règles déclenchées | LW-001 force brute (10), LW-002 pulvérisation (5), LW-005 IP suspecte (7) |

Exemple : une même IP a essayé 19 comptes différents (`admin`, `cisco`, `guest`, `ftpuser`…) en
1,4 minute, signalée comme pulvérisation de mots de passe (LW-002) et IP suspecte (LW-005).

## Ce que cela montre, et ce que cela ne montre pas

* Le parseur lit de vraies sorties OpenSSH sans aucune ligne mal formée, et les règles se
  déclenchent sur de vraies attaques automatisées (balayage de noms de comptes courants).
* Il n'y a **pas de vérité terrain** pour ce fichier : impossible de calculer précision et rappel,
  on vérifie seulement à la lecture que les alertes sont plausibles.
* Les lignes « message repeated N times » et les résumés PAM sont ignorés : certaines tentatives
  sont donc sous-comptées.