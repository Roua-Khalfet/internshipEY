"""
Composant 1 — Synchronisation automatique du repo nuclei-templates.

Fonctions principales :
    sync_repo()          : Clone ou pull le repo, retourne le nouveau commit hash
    get_changed_files()  : Détecte les fichiers nouveaux/modifiés/supprimés via git diff
    load_last_commit()   : Charge le dernier commit traité
    save_last_commit()   : Sauvegarde le commit courant
"""

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from nuclei_kb.config import (
    LAST_COMMIT_FILE,
    REPO_DIR,
    REPO_URL,
    TEMPLATE_EXTENSIONS,
)

logger = logging.getLogger(__name__)


# ── Structures de données ──────────────────────────────────────────

@dataclass
class SyncResult:
    """Résultat d'une opération de synchronisation."""
    old_commit: str | None
    new_commit: str
    is_first_run: bool
    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.modified or self.deleted)

    @property
    def total_changes(self) -> int:
        return len(self.added) + len(self.modified) + len(self.deleted)


# ── Helpers git ────────────────────────────────────────────────────

def _run_git(*args: str, cwd: Path | None = None) -> str:
    """Exécute une commande git et retourne stdout."""
    cmd = ["git"] + list(args)
    cwd = cwd or REPO_DIR
    logger.debug("Exécution: %s (cwd=%s)", " ".join(cmd), cwd)
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=600,  # 10 min max pour le clone
    )
    if result.returncode != 0:
        logger.error("Git error (code %d): %s", result.returncode, result.stderr.strip())
        raise RuntimeError(f"Git command failed: {' '.join(cmd)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def _get_head_commit(repo_dir: Path | None = None) -> str:
    """Retourne le hash du commit HEAD."""
    return _run_git("rev-parse", "HEAD", cwd=repo_dir)


def _is_template_file(filepath: str) -> bool:
    """Vérifie si le fichier est un template YAML."""
    return Path(filepath).suffix.lower() in TEMPLATE_EXTENSIONS


# ── Gestion du dernier commit ──────────────────────────────────────

def load_last_commit() -> str | None:
    """Charge le dernier commit traité depuis le fichier de suivi."""
    if LAST_COMMIT_FILE.exists():
        commit = LAST_COMMIT_FILE.read_text().strip()
        if commit:
            logger.info("Dernier commit traite: %s", commit[:12])
            return commit
    logger.info("Aucun commit precedent trouve (premier run)")
    return None


def save_last_commit(commit_hash: str) -> None:
    """Sauvegarde le commit courant dans le fichier de suivi."""
    LAST_COMMIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_COMMIT_FILE.write_text(commit_hash)
    logger.info("Commit sauvegarde: %s", commit_hash[:12])


# ── Synchronisation ────────────────────────────────────────────────

def clone_repo() -> str:
    """Clone le repo nuclei-templates. Retourne le hash HEAD."""
    logger.info("Clonage du repo %s -> %s", REPO_URL, REPO_DIR)
    REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
    _run_git(
        "clone", "--depth=1", REPO_URL, str(REPO_DIR),
        cwd=REPO_DIR.parent,
    )
    head = _get_head_commit()
    logger.info("Repo clone avec succes (HEAD: %s)", head[:12])
    return head


def pull_repo() -> str:
    """Pull les dernières modifications. Retourne le nouveau hash HEAD."""
    logger.info("Pull du repo %s", REPO_DIR)
    # Unshallow seulement si le repo est effectivement shallow
    shallow_file = REPO_DIR / ".git" / "shallow"
    if shallow_file.exists():
        logger.info("Repo shallow detecte, fetch --unshallow en cours...")
        try:
            _run_git("fetch", "--unshallow", cwd=REPO_DIR)
        except RuntimeError:
            logger.warning("fetch --unshallow a echoue (repo deja complet?)")
    _run_git("pull", "--ff-only", cwd=REPO_DIR)
    head = _get_head_commit()
    logger.info("Pull termine (HEAD: %s)", head[:12])
    return head


def _get_all_template_files() -> list[str]:
    """Liste tous les fichiers template du repo (pour le premier run)."""
    output = _run_git(
        "ls-files", "--", "*.yaml", "*.yml",
        cwd=REPO_DIR,
    )
    files = [f for f in output.splitlines() if _is_template_file(f)]
    logger.info("Premier run: %d fichiers template trouves", len(files))
    return files


def get_changed_files(old_commit: str, new_commit: str) -> dict[str, list[str]]:
    """
    Détecte les fichiers changés entre deux commits via git diff.

    Retourne:
        {"added": [...], "modified": [...], "deleted": [...]}
    """
    output = _run_git(
        "diff", "--name-status", old_commit, new_commit,
        cwd=REPO_DIR,
    )

    changes: dict[str, list[str]] = {"added": [], "modified": [], "deleted": []}
    status_map = {"A": "added", "M": "modified", "D": "deleted"}

    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            logger.warning("Ligne git diff inattendue: %s", line)
            continue

        status_code, filepath = parts[0].strip(), parts[1].strip()

        # Gérer les renames (R100, R090, etc.)
        if status_code.startswith("R"):
            # Pour un rename, on traite comme delete ancien + add nouveau
            rename_parts = filepath.split("\t")
            if len(rename_parts) == 2:
                old_file, new_file = rename_parts
                if _is_template_file(old_file):
                    changes["deleted"].append(old_file)
                if _is_template_file(new_file):
                    changes["added"].append(new_file)
            continue

        change_type = status_map.get(status_code[0])
        if change_type and _is_template_file(filepath):
            changes[change_type].append(filepath)

    logger.info(
        "Changements detectes: +%d ajoutes, ~%d modifies, -%d supprimes",
        len(changes["added"]), len(changes["modified"]), len(changes["deleted"]),
    )
    return changes


# ── Point d'entrée principal ───────────────────────────────────────

def sync_repo() -> SyncResult:
    """
    Synchronise le repo nuclei-templates.

    - Clone si le repo n'existe pas localement
    - Pull sinon
    - Détecte les changements depuis le dernier commit traité

    Retourne un SyncResult avec la liste des fichiers changés.
    """
    old_commit = load_last_commit()
    is_first_run = not REPO_DIR.exists() or not (REPO_DIR / ".git").exists()

    if is_first_run:
        new_commit = clone_repo()
        all_files = _get_all_template_files()
        result = SyncResult(
            old_commit=None,
            new_commit=new_commit,
            is_first_run=True,
            added=all_files,
        )
    else:
        new_commit = pull_repo()

        if old_commit and old_commit != new_commit:
            changes = get_changed_files(old_commit, new_commit)
            result = SyncResult(
                old_commit=old_commit,
                new_commit=new_commit,
                is_first_run=False,
                **changes,
            )
        elif old_commit is None:
            # Repo existe mais pas de commit précédent → traiter tout
            all_files = _get_all_template_files()
            result = SyncResult(
                old_commit=None,
                new_commit=new_commit,
                is_first_run=False,
                added=all_files,
            )
        else:
            logger.info("Aucun changement (meme commit: %s)", new_commit[:12])
            result = SyncResult(
                old_commit=old_commit,
                new_commit=new_commit,
                is_first_run=False,
            )

    save_last_commit(new_commit)
    return result
