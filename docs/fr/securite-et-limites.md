# Sécurité et limites

*English version: [../security-and-limitations.md](../security-and-limitations.md)*

## Périmètre et éthique

LogWarden est un outil **défensif et pédagogique**. Il lit uniquement les fichiers qu'on lui
fournit. Il n'effectue aucun scan réseau ni test actif et ne contacte aucun service externe (la
télémétrie de Streamlit est désactivée). Toutes les données de démo sont synthétiques et
utilisent les plages d'adresses de documentation de la RFC 5737.

## Modèle de menace de l'outil lui-même

Le contenu des journaux est **contrôlé par l'attaquant** : il choisit le nom de compte qu'il
tape. Tout endroit où circulent des données de journaux est traité comme une entrée non fiable.

| Risque | Mesure | Test |
|---|---|---|
| Exécution de commandes depuis les logs | uniquement des expressions régulières / `json.loads` ; rien n'est évalué ni passé à un shell ; le lanceur du tableau de bord utilise une liste d'arguments fixe (pas de `shell=True`) | tests des parseurs |
| Injection SQL | toutes les requêtes sont paramétrées | `test_sql_injection_payload_is_stored_as_data` |
| Injection de séquences d'échappement terminal (`\x1b[...`) | caractères de contrôle remplacés par `?` avant stockage/affichage | `test_control_characters_are_neutralised` |
| Injection Markdown/HTML dans le tableau de bord (un compte nommé `![x](http://evil/p.png)` ferait contacter un serveur par le navigateur) | texte issu des logs échappé ou affiché dans des tableaux ; pas de `unsafe_allow_html` | `test_dashboard_markdown_escape` |
| Injection de formules CSV à l'ouverture dans un tableur | cellules commençant par `= + - @` préfixées par `'` | `test_csv_injection_is_neutralised` |
| Secrets dans les logs (client qui journalise mots de passe/jetons) | champs `redacted_fields` remplacés par `[REDACTED]` avant stockage | `test_sensitive_fields_are_redacted` |
| Fichiers énormes ou hostiles (mémoire, JSON très imbriqué) | taille max (50 Mo), longueur de ligne max, détection des binaires, `RecursionError` gérée | tests d'importation |
| Tableau de bord exposé sur le réseau | écoute uniquement sur `127.0.0.1` ; base ouverte en lecture seule ; envoi de fichiers uniquement dans l'onglet bas à sable (2 Mo, analyse en mémoire, rien n'est enregistré, IP et comptes masqués) | vérification `ss -ltn`, test lecture seule |
| Chargement de modèle dangereux | modèle ML jamais sérialisé (pas de pickle) | conception |
| Base corrompue ou non inscriptible | `StorageError` claire et traduite ; transactions annulées | tests de stockage |

Risques résiduels connus : les dépendances (Streamlit, scikit-learn, matplotlib) sont du code
tiers ; lancer `pip-audit` avant tout usage réel. `reports/` et la base contiennent des comptes
et IP issus des logs et doivent être protégés comme les logs eux-mêmes.

## Limites fonctionnelles

* **Deux formats seulement** : messages OpenSSH dans syslog et format JSON de l'application de
  démo. D'autres sources exigent un nouveau parseur (interface réduite :
  `parse_line(str) -> Event | Skip | Malformed`).
* **Traitement par lots**, pas en temps réel : pas de `tail -f`, pas de flux.
* **Syslog sans année** : fournie par `--year` ; le passage décembre→janvier est déduit. Un
  horodatage traditionnel sans fuseau est interprété avec `--tz` (UTC par défaut). Les horodatages
  JSON sans fuseau sont lus en UTC.
* **Dédoublonnage par contenu** : deux événements réellement distincts produisant des lignes
  identiques au même horodatage sont comptés une fois.
* **Règles par IP** : une attaque répartie sur de nombreuses IP (botnet) échappe à LW-001/LW-002 ;
  un attaquant derrière une IP partagée (NAT, proxy) peut provoquer des faux positifs.
* **Pas de liste blanche ni de renseignement sur les menaces** : pas de GeoIP ni de réputation
  (il faudrait un service externe).
* **Seuils génériques**, non ajustés sur du trafic réel.
* **Évaluation uniquement sur données synthétiques** (voir [ml.md](ml.md)).
* **Mono-utilisateur, local** : pas d'authentification sur le tableau de bord (acceptable
  uniquement parce qu'il n'écoute que sur localhost).

## Améliorations possibles

1. Nouveaux parseurs : `journalctl -o json`, journaux d'accès nginx/Apache, événements de sécurité
   Windows (export JSON d'EVTX).
2. Export des alertes dans un format standard (ECS, règles de type Sigma, syslog/CEF vers un SIEM).
3. Profils par utilisateur (IP et horaires habituels) pour réduire les faux positifs de LW-004.
4. Règle d'attaque distribuée : nombreuses IP visant le même compte.
5. Cycle de vie des alertes dans le tableau de bord (prise en compte, faux positif), ce qui
   imposerait un accès en écriture et une authentification.
6. Évaluation sur un jeu public étiqueté dont la licence le permet.
7. `pip-audit` et `bandit` dans l'intégration continue.
