"""
Point d'entrée principal du pipeline nuclei-templates.

Orchestre : synchronisation git → parsing YAML → stockage SQLite.

Usage:
    python scripts/run_pipeline.py
    python scripts/run_pipeline.py --full   # Force un re-scan complet
"""

import argparse
import logging
import sys
from pathlib import Path

# Ajouter le répertoire parent au path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nuclei_kb.config import LOG_FILE, LOG_FORMAT, LOG_LEVEL
from nuclei_kb.sync import sync_repo, _get_all_template_files, load_last_commit, save_last_commit, _get_head_commit
from nuclei_kb.parser import parse_templates
from nuclei_kb.database import NucleiDatabase
from nuclei_kb.config import REPO_DIR


def setup_logging():
    """Configure le logging vers fichier + console."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def run_pipeline(full_scan: bool = False):
    """Exécute le pipeline complet."""
    logger = logging.getLogger("pipeline")
    logger.info("=" * 60)
    logger.info("Demarrage du pipeline nuclei-templates")
    logger.info("=" * 60)

    # ── Étape 1 : Synchronisation ──────────────────────────────────
    logger.info("[SYNC] Etape 1/3 -- Synchronisation du repo...")
    sync_result = sync_repo()

    if full_scan:
        logger.info("[FULL] Mode full-scan : traitement de tous les fichiers")
        all_files = _get_all_template_files()
        sync_result.added = all_files
        sync_result.modified = []
        sync_result.deleted = []

    logger.info(
        "Sync terminee: %s (first_run=%s, changes=%d)",
        sync_result.new_commit[:12],
        sync_result.is_first_run,
        sync_result.total_changes,
    )

    if not sync_result.has_changes:
        logger.info("[OK] Aucun changement detecte. Pipeline termine.")
        return

    # ── Étape 2 : Parsing ──────────────────────────────────────────
    logger.info("[PARSE] Etape 2/3 -- Parsing des templates...")

    added_templates = parse_templates(sync_result.added)
    modified_templates = parse_templates(sync_result.modified)

    # Pour les suppressions, on extrait l'ID depuis le nom du fichier
    # ou depuis la base existante
    deleted_ids = []
    with NucleiDatabase() as db:
        for fp in sync_result.deleted:
            # Chercher l'ID dans la base par file_path
            conn = db.connect()
            row = conn.execute(
                "SELECT template_id FROM templates WHERE file_path = ?", (fp,)
            ).fetchone()
            if row:
                deleted_ids.append(row["template_id"])

    logger.info(
        "Parsing: %d ajoutes, %d modifies, %d a supprimer",
        len(added_templates), len(modified_templates), len(deleted_ids),
    )

    # ── Étape 3 : Stockage ─────────────────────────────────────────
    logger.info("[DB] Etape 3/3 -- Mise a jour de la base SQLite...")

    with NucleiDatabase() as db:
        stats = db.process_sync(
            added=added_templates,
            modified=modified_templates,
            deleted_ids=deleted_ids,
            commit_hash=sync_result.new_commit,
        )

    logger.info("=" * 60)
    logger.info("[OK] Pipeline termine avec succes!")
    logger.info(
        "   +%d ajoutes | ~%d modifies | -%d supprimes | =%d inchanges",
        stats["added"], stats["modified"], stats["deleted"], stats["unchanged"],
    )
    logger.info("   Total en base: voir `python -c \"from nuclei_kb.queries import get_stats; print(get_stats())\"`")
    logger.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Pipeline nuclei-templates KB")
    parser.add_argument(
        "--full", action="store_true",
        help="Force un scan complet de tous les templates (ignore le diff incrémental)",
    )
    args = parser.parse_args()

    setup_logging()
    try:
        run_pipeline(full_scan=args.full)
    except Exception as e:
        logging.getLogger("pipeline").exception("[FAIL] Erreur fatale: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
