"""
nuclei_kb — Pipeline de base de connaissance auto-actualisée
à partir du repo nuclei-templates de ProjectDiscovery.

Modules:
    config   : Configuration centralisée (chemins, constantes)
    sync     : Synchronisation git du repo nuclei-templates
    parser   : Parsing YAML des templates
    database : Schéma SQLite + opérations CRUD
    queries  : Fonctions de requête prêtes à l'emploi
    dashboard: Dashboard Streamlit interactif
"""

__version__ = "1.0.0"
