"""
Configuration centralisée pour le pipeline nuclei-templates.
Tous les chemins sont relatifs à la racine du projet (BASE_DIR).
"""

from pathlib import Path

# ── Répertoire racine du projet ────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent

# ── Répertoire de données ──────────────────────────────────────────
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# ── Repo nuclei-templates ─────────────────────────────────────────
REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
REPO_DIR = DATA_DIR / "nuclei-templates"

# ── Base de données SQLite ─────────────────────────────────────────
DB_PATH = DATA_DIR / "nuclei_kb.db"

# ── Fichier de suivi du dernier commit traité ──────────────────────
LAST_COMMIT_FILE = DATA_DIR / "last_commit.txt"

# ── Logging ────────────────────────────────────────────────────────
LOG_FILE = LOGS_DIR / "pipeline.log"
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"

# ── Protocoles reconnus dans les templates nuclei ──────────────────
KNOWN_PROTOCOLS = frozenset({
    "http", "dns", "network", "tcp", "ssl",
    "headless", "code", "javascript", "file",
    "whois", "websocket",
})

# ── Extensions de templates à traiter ──────────────────────────────
TEMPLATE_EXTENSIONS = frozenset({".yaml", ".yml"})
