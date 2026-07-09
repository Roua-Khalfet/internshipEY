# 🛡️ Nuclei Templates — Knowledge Base Pipeline

Pipeline Python pour synchroniser, parser et exploiter les templates [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) comme base de connaissance pour l'entraînement d'un modèle de détection d'anomalies réseau.

## 🚀 Installation

```bash
# Se placer dans le projet
cd C:\Users\rarou\Desktop\internship

# Créer l'environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
.\venv\Scripts\activate        # Windows (PowerShell)
# source venv/bin/activate     # Linux / macOS

# Installer les dépendances
pip install -r requirements.txt
```

> ⚠️ **Important** : Toujours activer le venv avant de lancer les scripts.

## 📦 Utilisation

### 1. Exécuter le pipeline complet

```bash
# Premier run : clone le repo + parse tout + stocke en SQLite
python scripts/run_pipeline.py

# Runs suivants : pull les changements + traite uniquement le delta
python scripts/run_pipeline.py

# Force un re-scan complet
python scripts/run_pipeline.py --full
```

### 2. Requêtes Python

```python
from nuclei_kb.queries import (
    get_templates_by_tag,
    get_templates_by_protocol,
    get_new_templates_since,
    get_changes_this_week,
    export_tag_list_for_nuclei_run,
    get_stats,
)

# Templates DNS
dns_templates = get_templates_by_tag("dns")

# Templates réseau (protocole network/tcp)
network = get_templates_by_protocol("network")

# Nouveautés depuis une date
new = get_new_templates_since("2024-06-01")

# Commande nuclei ciblée
cmd = export_tag_list_for_nuclei_run(["dns", "network", "sqli"])
print(cmd)  # nuclei -tags dns,network,sqli -t data/nuclei-templates/ -u <TARGET>

# Statistiques globales
stats = get_stats()
```

### 3. Dashboard Streamlit

```bash
streamlit run nuclei_kb/dashboard.py
```

### 4. Rapport Markdown

```bash
python scripts/generate_report.py --output data/report.md
```

## ⚙️ Automatisation

- **GitHub Actions** : `.github/workflows/sync_nuclei.yml` — exécution quotidienne à 2h UTC
- **Cron / Task Scheduler** : voir `crontab_example.txt`

## 📁 Structure

```
├── nuclei_kb/               # Package Python principal
│   ├── config.py            # Configuration centralisée
│   ├── sync.py              # Synchronisation git
│   ├── parser.py            # Parsing YAML des templates
│   ├── database.py          # Stockage SQLite
│   ├── queries.py           # Fonctions de requête
│   └── dashboard.py         # Dashboard Streamlit
├── scripts/
│   ├── run_pipeline.py      # Point d'entrée pipeline
│   └── generate_report.py   # Génération rapport markdown
├── data/                    # Données (gitignored)
│   ├── nuclei-templates/    # Repo cloné
│   ├── nuclei_kb.db         # Base SQLite
│   └── last_commit.txt      # Dernier commit traité
├── logs/                    # Logs du pipeline
├── .github/workflows/       # GitHub Actions
├── requirements.txt
└── README.md
```

## 📊 Schéma SQLite

### Table `templates`
| Colonne | Type | Description |
|---------|------|-------------|
| template_id | TEXT PK | ID unique du template |
| name | TEXT | Nom du template |
| severity | TEXT | critical/high/medium/low/info |
| tags | TEXT | Tags CSV |
| protocol | TEXT | http/dns/network/tcp/ssl/... |
| cve_id | TEXT | CVE associé |
| cwe_id | TEXT | CWE associé |
| cvss_score | REAL | Score CVSS |
| description | TEXT | Description |
| file_path | TEXT | Chemin dans le repo |
| content_hash | TEXT | SHA256 du contenu |
| date_first_seen | TEXT | Date de première détection |
| date_last_updated | TEXT | Date de dernière mise à jour |

### Table `change_log`
| Colonne | Type | Description |
|---------|------|-------------|
| template_id | TEXT | ID du template concerné |
| change_type | TEXT | added/modified/deleted |
| change_date | TEXT | Date du changement |
| commit_hash | TEXT | Hash du commit associé |
| details | TEXT | Détails JSON des modifications |

---

## 📝 Changelog

### v1.0.0 — 2026-07-06

> **Mise en place initiale du pipeline complet**

- ✅ Création de la structure du projet (`nuclei_kb/` package + `scripts/`)
- ✅ **`nuclei_kb/config.py`** — Configuration centralisée (chemins, protocoles, extensions)
- ✅ **`nuclei_kb/sync.py`** — Synchronisation git automatique : clone/pull + détection des changements via `git diff --name-status` + suivi du dernier commit traité
- ✅ **`nuclei_kb/parser.py`** — Parsing YAML des templates avec extraction : id, name, severity, tags, protocol, CVE/CWE, CVSS, description, content_hash (SHA256). Gestion robuste des erreurs (templates malformés loggés sans crash)
- ✅ **`nuclei_kb/database.py`** — Base SQLite avec tables `templates` + `change_log`, logique upsert basée sur `content_hash`, index de performance
- ✅ **`nuclei_kb/queries.py`** — Fonctions de requête : `get_templates_by_tag()`, `get_templates_by_protocol()`, `get_new_templates_since()`, `get_changes_this_week()`, `export_tag_list_for_nuclei_run()`, `get_stats()`
- ✅ **`nuclei_kb/dashboard.py`** — Dashboard Streamlit avec KPIs, charts sévérité/protocole, top 20 tags, table DNS/Network de la semaine, générateur de commande Nuclei
- ✅ **`scripts/run_pipeline.py`** — Orchestrateur : sync → parse → store (mode incrémental + `--full`)
- ✅ **`scripts/generate_report.py`** — Génération de rapport Markdown statique
- ✅ **`.github/workflows/sync_nuclei.yml`** — GitHub Actions (cron quotidien 2h UTC)
- ✅ **`crontab_example.txt`** — Config cron Linux/WSL + instructions Windows Task Scheduler
- ✅ Environnement virtuel Python (`venv/`) créé + dépendances installées (PyYAML, Streamlit, Plotly, Pandas)
