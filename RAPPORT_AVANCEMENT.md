# Rapport d'avancement — Pipeline Nuclei Templates Knowledge Base

**Stagiaire** : Roua 
**Date** : 07 juillet 2026  
**Projet** : Construction d'une base de connaissance automatisee a partir des templates Nuclei

---

## 1. Contexte et objectif

[Nuclei](https://github.com/projectdiscovery/nuclei) est un scanner de vulnerabilites open-source developpe par ProjectDiscovery. Il s'appuie sur un depot GitHub de **templates YAML** (`nuclei-templates`) qui decrivent chacun une vulnerabilite, une misconfiguration ou une technique de detection.

**L'objectif de ce travail** est de construire un pipeline automatise qui :
1. Synchronise ce depot GitHub en local
2. Parse les milliers de templates YAML pour en extraire les metadonnees structurees
3. Les stocke dans une base SQLite interrogeable
4. Permet des requetes analytiques et une visualisation via un dashboard

Ce pipeline sert de **base de connaissance (Knowledge Base)** pour alimenter un futur modele de detection d'anomalies reseau.

---

## 2. Ce qui a ete realise

### 2.1 Architecture du projet

Le projet est structure en un package Python modulaire (`nuclei_kb/`) avec des scripts d'orchestration :

```
internship/
├── nuclei_kb/                # Package Python principal
│   ├── config.py             # Configuration centralisee
│   ├── sync.py               # Synchronisation git (clone/pull)
│   ├── parser.py             # Parsing YAML des templates
│   ├── database.py           # Stockage SQLite
│   ├── queries.py            # Fonctions de requete
│   └── dashboard.py          # Dashboard Streamlit
├── scripts/
│   ├── run_pipeline.py       # Point d'entree du pipeline
│   └── generate_report.py    # Generation de rapports
├── data/                     # Donnees generees (gitignore)
│   ├── nuclei-templates/     # Repo clone depuis GitHub
│   ├── nuclei_kb.db          # Base SQLite
│   └── last_commit.txt       # Suivi du dernier commit
├── .github/workflows/        # Automatisation GitHub Actions
├── requirements.txt          # Dependances Python
└── README.md
```

### 2.2 Detail des composants developpes

#### a) `config.py` — Configuration centralisee
- Tous les chemins (donnees, logs, BDD) sont definis relativement a la racine du projet
- URL du repo GitHub, protocoles reconnus, extensions a traiter
- Configuration du logging (format, niveau, fichier de sortie)

#### b) `sync.py` — Synchronisation Git automatique
- **Premier run** : clone le repo avec `git clone --depth=1` (clone superficiel pour la rapidite)
- **Runs suivants** : fait un `git pull` et detecte les changements via `git diff --name-status`
- Classe les fichiers en 3 categories : **ajoutes**, **modifies**, **supprimes**
- Gere les renames Git (traites comme suppression + ajout)
- Sauvegarde le hash du dernier commit traite pour le suivi incremental

#### c) `parser.py` — Parsing YAML des templates
Chaque template YAML est parse pour en extraire :

| Champ extrait   | Description                                |
|-----------------|--------------------------------------------|
| `template_id`   | Identifiant unique du template             |
| `name`          | Nom lisible                                |
| `severity`      | Niveau : critical, high, medium, low, info |
| `tags`          | Tags CSV (ex: "dns,takeover,azure")        |
| `protocol`      | Protocole : http, dns, tcp, ssl, etc.      |
| `cve_id`        | Reference CVE associee                     |
| `cwe_id`        | Reference CWE associee                     |
| `cvss_score`    | Score CVSS numerique                       |
| `description`   | Description textuelle                      |
| `content_hash`  | SHA256 du contenu (pour detecter les modifications) |

**Gestion d'erreurs robuste** : les templates malformes sont logges et ignores sans faire crasher le pipeline.

#### d) `database.py` — Base SQLite
- Table `templates` : stocke toutes les metadonnees extraites
- Table `change_log` : historise chaque changement (ajout/modification/suppression) avec le commit associe
- Logique **upsert** basee sur le `content_hash` : un template n'est mis a jour que si son contenu a reellement change
- Index de performance sur les colonnes les plus interrogees

#### e) `queries.py` — Fonctions de requete
Fonctions pretes a l'emploi pour exploiter la base :
- `get_templates_by_tag("dns")` — Templates par tag
- `get_templates_by_protocol("network")` — Templates par protocole
- `get_new_templates_since("2024-06-01")` — Nouveautes depuis une date
- `get_changes_this_week()` — Changements de la semaine
- `export_tag_list_for_nuclei_run(["dns", "sqli"])` — Genere une commande nuclei ciblee
- `get_stats()` — Statistiques globales (total, repartition severite/protocole, top tags)

#### f) `dashboard.py` — Dashboard Streamlit
Interface web interactive avec :
- KPIs principaux (total templates, critiques, hauts, etc.)
- Graphiques de repartition par severite et protocole
- Top 20 des tags les plus utilises
- Table des templates DNS/Network de la semaine
- Generateur de commande Nuclei personnalisee

#### g) Automatisation
- **GitHub Actions** (`.github/workflows/sync_nuclei.yml`) : execution quotidienne a 2h UTC
- **Crontab / Task Scheduler** : instructions fournies pour Linux et Windows

---

## 3. Test et validation — 07 juillet 2026

Le pipeline a ete execute avec succes. Voici les resultats :

### Execution

```
python scripts/run_pipeline.py
```

### Resultats

| Etape                    | Statut | Detail                                     |
|--------------------------|--------|--------------------------------------------|
| Clone depuis GitHub      | OK     | Repo `nuclei-templates` clone              |
| Parsing YAML             | OK     | **13 376 templates** parses avec succes    |
| Fichiers ignores         | OK     | 44 fichiers non-template ignores proprement|
| Stockage SQLite          | OK     | 13 376 enregistrements inseres             |
| Suivi du commit          | OK     | Commit `40bc7b1b` sauvegarde               |
| Requete de verification  | OK     | `get_templates_by_tag('dns')` = 45 resultats|

### Statistiques de la base

**Repartition par severite :**

| Severite | Nombre  |  %    |
|----------|---------|-------|
| Info     | 5 049   | 37.7% |
| High     | 2 923   | 21.9% |
| Medium   | 2 808   | 21.0% |
| Critical | 1 826   | 13.7% |
| Low      | 505     | 3.8%  |
| Unknown  | 265     | 2.0%  |

**Repartition par protocole :**

| Protocole  | Nombre  |  %    |
|------------|---------|-------|
| HTTP       | 11 272  | 84.3% |
| Code       | 940     | 7.0%  |
| File       | 447     | 3.3%  |
| TCP        | 285     | 2.1%  |
| JavaScript | 125     | 0.9%  |
| SSL        | 39      | 0.3%  |
| DNS        | 34      | 0.3%  |
| Headless   | 27      | 0.2%  |

**Top 10 tags les plus frequents :**

| Tag        | Occurrences |
|------------|-------------|
| vuln       | 6 630       |
| cve        | 4 294       |
| discovery  | 3 729       |
| vkev       | 1 801       |
| wordpress  | 1 656       |
| panel      | 1 566       |
| wp-plugin  | 1 473       |
| exposure   | 1 465       |
| xss        | 1 409       |
| osint      | 1 131       |

---

## 4. Corrections apportees le 07/07

- **Encodage console Windows** : les emojis et caracteres accentues dans les messages de log causaient des `UnicodeEncodeError` sur la console Windows (encodage `cp1252`). Tous les messages de log ont ete convertis en ASCII pur.
- **Optimisation du pull Git** : le `git fetch --unshallow` (qui telecharge tout l'historique) ne s'execute plus que si le repo est effectivement en mode shallow, evitant un telechargement inutile de plusieurs minutes a chaque run.

---

## 5. Prochaines etapes envisagees

1. **Finaliser le mode incremental** : tester un run apres que de nouveaux templates soient ajoutes au repo upstream
2. **Dashboard Streamlit** : lancer et valider le dashboard interactif
3. **Integration avec le modele** : utiliser les donnees extraites pour alimenter le modele de detection d'anomalies
4. **Filtrage avance** : enrichir les requetes (par CVE, par score CVSS, par date, etc.)
5. **Rapport automatique** : generer un rapport hebdomadaire des nouveaux templates

---

## 6. Technologies utilisees

| Technologie    | Usage                              |
|----------------|------------------------------------|
| Python 3.12    | Langage principal                  |
| PyYAML         | Parsing des templates YAML         |
| SQLite         | Base de donnees locale             |
| Git            | Synchronisation du repo            |
| Streamlit      | Dashboard web interactif           |
| Plotly/Pandas  | Visualisation et manipulation data |
| GitHub Actions | Automatisation CI/CD               |

---

*Document genere le 07/07/2026*
