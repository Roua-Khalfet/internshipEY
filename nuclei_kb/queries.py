"""
Composant 4 — Fonctions de requête prêtes à l'emploi.

Fonctions pour interroger la base de connaissance nuclei-templates
et générer des commandes nuclei ciblées.
"""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nuclei_kb.config import DB_PATH, REPO_DIR

logger = logging.getLogger(__name__)


def _get_conn(db_path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path or DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _rows_to_dicts(rows) -> list[dict]:
    return [dict(r) for r in rows]


# ── Requêtes principales ──────────────────────────────────────────

def get_templates_by_tag(tag: str, db_path: Path | None = None) -> list[dict]:
    """
    Récupère tous les templates ayant un tag donné.

    Exemples:
        get_templates_by_tag('dns')
        get_templates_by_tag('network')
        get_templates_by_tag('misconfiguration')
    """
    conn = _get_conn(db_path)
    try:
        # Recherche exacte du tag dans la liste CSV
        # Couvre : "dns,...", "...,dns,...", "...,dns"
        rows = conn.execute(
            """SELECT * FROM templates
               WHERE ',' || tags || ',' LIKE ?
               ORDER BY severity, name""",
            (f"%,{tag},%",),
        ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        conn.close()


def get_new_templates_since(date: str, db_path: Path | None = None) -> list[dict]:
    """
    Récupère les templates ajoutés depuis une date.

    Args:
        date: Format 'YYYY-MM-DD' ou 'YYYY-MM-DD HH:MM:SS'

    Exemple:
        get_new_templates_since('2024-06-01')
    """
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM templates
               WHERE date_first_seen >= ?
               ORDER BY date_first_seen DESC""",
            (date,),
        ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        conn.close()


def get_templates_by_protocol(protocol: str, db_path: Path | None = None) -> list[dict]:
    """
    Récupère les templates utilisant un protocole donné.

    Exemples:
        get_templates_by_protocol('dns')
        get_templates_by_protocol('tcp')
        get_templates_by_protocol('network')
    """
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM templates
               WHERE protocol = ?
               ORDER BY severity, name""",
            (protocol.lower(),),
        ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        conn.close()


def get_changes_since(date: str, db_path: Path | None = None) -> list[dict]:
    """
    Récupère l'historique des changements depuis une date.
    Utile pour répondre à "qu'est-ce qui a changé cette semaine ?".

    Args:
        date: Format 'YYYY-MM-DD'
    """
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM change_log
               WHERE change_date >= ?
               ORDER BY change_date DESC""",
            (date,),
        ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        conn.close()


def get_changes_this_week(db_path: Path | None = None) -> list[dict]:
    """Raccourci : changements des 7 derniers jours."""
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    return get_changes_since(week_ago, db_path)


def export_tag_list_for_nuclei_run(
    tags: list[str],
    repo_dir: Path | None = None,
) -> str:
    """
    Génère la commande nuclei pour lancer un scan ciblé par tags.

    Args:
        tags: Liste de tags (ex: ['dns', 'network'])
        repo_dir: Chemin du repo local

    Returns:
        Commande shell prête à exécuter

    Exemple:
        >>> export_tag_list_for_nuclei_run(['dns', 'network'])
        'nuclei -tags dns,network -t /path/to/nuclei-templates/ -u <TARGET>'
    """
    repo = repo_dir or REPO_DIR
    tags_str = ",".join(tags)
    return f"nuclei -tags {tags_str} -t {repo}/ -u <TARGET>"


# ── Statistiques ───────────────────────────────────────────────────

def get_stats(db_path: Path | None = None) -> dict:
    """
    Statistiques globales de la base de connaissance.

    Retourne:
        {
            "total": int,
            "by_severity": {"critical": N, "high": N, ...},
            "by_protocol": {"http": N, "dns": N, ...},
            "top_tags": [("tag", count), ...],
            "new_this_week": int,
        }
    """
    conn = _get_conn(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) FROM templates").fetchone()[0]

        by_severity = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM templates GROUP BY severity ORDER BY cnt DESC"
        ):
            by_severity[row["severity"]] = row["cnt"]

        by_protocol = {}
        for row in conn.execute(
            "SELECT protocol, COUNT(*) as cnt FROM templates GROUP BY protocol ORDER BY cnt DESC"
        ):
            by_protocol[row["protocol"]] = row["cnt"]

        # Top tags (split CSV et comptage)
        all_tags: dict[str, int] = {}
        for row in conn.execute("SELECT tags FROM templates WHERE tags != ''"):
            for tag in row["tags"].split(","):
                tag = tag.strip()
                if tag:
                    all_tags[tag] = all_tags.get(tag, 0) + 1
        top_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)[:30]

        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
        new_this_week = conn.execute(
            "SELECT COUNT(*) FROM templates WHERE date_first_seen >= ?", (week_ago,)
        ).fetchone()[0]

        return {
            "total": total,
            "by_severity": by_severity,
            "by_protocol": by_protocol,
            "top_tags": top_tags,
            "new_this_week": new_this_week,
        }
    finally:
        conn.close()


def get_templates_by_severity(severity: str, db_path: Path | None = None) -> list[dict]:
    """Récupère les templates par niveau de sévérité."""
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM templates WHERE severity = ? ORDER BY name",
            (severity.lower(),),
        ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        conn.close()
