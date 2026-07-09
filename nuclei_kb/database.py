"""
Composant 3 — Stockage SQLite pour la base de connaissance nuclei-templates.

Tables :
    templates   : Métadonnées de chaque template (avec content_hash, dates)
    change_log  : Historique des ajouts/modifications/suppressions
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from nuclei_kb.config import DB_PATH
from nuclei_kb.parser import TemplateData

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS templates (
    template_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'unknown',
    tags            TEXT NOT NULL DEFAULT '',
    protocol        TEXT NOT NULL DEFAULT 'unknown',
    cve_id          TEXT,
    cwe_id          TEXT,
    cvss_score      REAL,
    description     TEXT,
    file_path       TEXT NOT NULL DEFAULT '',
    content_hash    TEXT NOT NULL DEFAULT '',
    date_first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    date_last_updated TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS change_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id     TEXT NOT NULL,
    change_type     TEXT NOT NULL CHECK(change_type IN ('added', 'modified', 'deleted')),
    change_date     TEXT NOT NULL DEFAULT (datetime('now')),
    commit_hash     TEXT,
    details         TEXT
);

CREATE INDEX IF NOT EXISTS idx_templates_severity ON templates(severity);
CREATE INDEX IF NOT EXISTS idx_templates_protocol ON templates(protocol);
CREATE INDEX IF NOT EXISTS idx_templates_date ON templates(date_first_seen);
CREATE INDEX IF NOT EXISTS idx_changelog_date ON change_log(change_date);
CREATE INDEX IF NOT EXISTS idx_changelog_tid ON change_log(template_id);
"""


class NucleiDatabase:
    """Gestionnaire de la base SQLite nuclei-templates."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA_SQL)
            self._conn.commit()
        return self._conn

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def get_template(self, template_id: str) -> dict | None:
        row = self.connect().execute(
            "SELECT * FROM templates WHERE template_id = ?", (template_id,)
        ).fetchone()
        return dict(row) if row else None

    def upsert_template(self, tpl: TemplateData, commit_hash: str | None = None) -> str:
        """Insert ou update. Retourne 'added', 'modified', ou 'unchanged'."""
        conn = self.connect()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        existing = self.get_template(tpl.template_id)

        if existing is None:
            conn.execute(
                """INSERT INTO templates
                   (template_id,name,severity,tags,protocol,cve_id,cwe_id,
                    cvss_score,description,file_path,content_hash,
                    date_first_seen,date_last_updated)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tpl.template_id, tpl.name, tpl.severity, tpl.tags,
                 tpl.protocol, tpl.cve_id, tpl.cwe_id, tpl.cvss_score,
                 tpl.description, tpl.file_path, tpl.content_hash, now, now),
            )
            self._log_change(tpl.template_id, "added", commit_hash)
            return "added"

        if existing["content_hash"] != tpl.content_hash:
            conn.execute(
                """UPDATE templates SET name=?,severity=?,tags=?,protocol=?,
                   cve_id=?,cwe_id=?,cvss_score=?,description=?,file_path=?,
                   content_hash=?,date_last_updated=? WHERE template_id=?""",
                (tpl.name, tpl.severity, tpl.tags, tpl.protocol,
                 tpl.cve_id, tpl.cwe_id, tpl.cvss_score, tpl.description,
                 tpl.file_path, tpl.content_hash, now, tpl.template_id),
            )
            self._log_change(tpl.template_id, "modified", commit_hash)
            return "modified"

        return "unchanged"

    def delete_template(self, template_id: str, commit_hash: str | None = None) -> bool:
        conn = self.connect()
        if self.get_template(template_id):
            conn.execute("DELETE FROM templates WHERE template_id=?", (template_id,))
            self._log_change(template_id, "deleted", commit_hash)
            return True
        return False

    def _log_change(self, template_id, change_type, commit_hash=None, details=None):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.connect().execute(
            "INSERT INTO change_log (template_id,change_type,change_date,commit_hash,details) VALUES (?,?,?,?,?)",
            (template_id, change_type, now, commit_hash, details),
        )

    def process_sync(self, added, modified, deleted_ids, commit_hash=None):
        """Traite un batch sync. Retourne stats dict."""
        conn = self.connect()
        stats = {"added": 0, "modified": 0, "deleted": 0, "unchanged": 0}
        try:
            for tpl in added + modified:
                stats[self.upsert_template(tpl, commit_hash)] += 1
            for tid in deleted_ids:
                if self.delete_template(tid, commit_hash):
                    stats["deleted"] += 1
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        logger.info("Batch: +%d ~%d -%d =%d", stats["added"], stats["modified"], stats["deleted"], stats["unchanged"])
        return stats

    def count_templates(self) -> int:
        row = self.connect().execute("SELECT COUNT(*) FROM templates").fetchone()
        return row[0] if row else 0
