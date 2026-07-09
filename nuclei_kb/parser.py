"""
Composant 2 — Parsing des templates nuclei (YAML).

Extrait les métadonnées structurées de chaque template :
id, name, severity, tags, protocol, CVE/CWE, CVSS, description, file_path.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from nuclei_kb.config import KNOWN_PROTOCOLS, REPO_DIR

logger = logging.getLogger(__name__)


@dataclass
class TemplateData:
    """Données extraites d'un template nuclei."""
    template_id: str
    name: str
    severity: str
    tags: str                    # CSV : "dns,takeover,azure"
    protocol: str                # http, dns, network, tcp, ssl, ...
    cve_id: str | None = None
    cwe_id: str | None = None
    cvss_score: float | None = None
    description: str | None = None
    file_path: str = ""          # chemin relatif dans le repo
    content_hash: str = ""       # SHA256 du contenu brut


def _compute_hash(content: bytes) -> str:
    """Calcule le SHA256 d'un contenu brut."""
    return hashlib.sha256(content).hexdigest()


def _detect_protocol(data: dict, file_path: str) -> str:
    """
    Détecte le protocole utilisé par le template.

    Stratégie :
    1. Chercher une clé racine correspondant à un protocole connu
    2. Sinon, inférer depuis le chemin du fichier (ex: dns/... → dns)
    3. Fallback : "unknown"
    """
    # 1. Clés racines du YAML
    for key in data:
        if isinstance(key, str) and key.lower() in KNOWN_PROTOCOLS:
            return key.lower()

    # 2. Inférence depuis le chemin
    path_parts = Path(file_path).parts
    for part in path_parts:
        if part.lower() in KNOWN_PROTOCOLS:
            return part.lower()

    return "unknown"


def _extract_classification(info: dict) -> dict:
    """Extrait les champs de classification (CVE, CWE, CVSS)."""
    classification = info.get("classification", {}) or {}
    result = {
        "cve_id": None,
        "cwe_id": None,
        "cvss_score": None,
    }

    # CVE-ID : peut être string ou liste
    cve = classification.get("cve-id")
    if isinstance(cve, list):
        result["cve_id"] = ",".join(str(c) for c in cve if c)
    elif cve:
        result["cve_id"] = str(cve)

    # CWE-ID
    cwe = classification.get("cwe-id")
    if isinstance(cwe, list):
        result["cwe_id"] = ",".join(str(c) for c in cwe if c)
    elif cwe:
        result["cwe_id"] = str(cwe)

    # CVSS Score
    cvss = classification.get("cvss-score")
    if cvss is not None:
        try:
            result["cvss_score"] = float(cvss)
        except (ValueError, TypeError):
            logger.debug("CVSS score invalide: %s", cvss)

    return result


def parse_template(file_path: str, repo_dir: Path | None = None) -> TemplateData | None:
    """
    Parse un fichier template YAML et extrait ses métadonnées.

    Args:
        file_path: Chemin relatif du template dans le repo
        repo_dir:  Répertoire racine du repo (défaut: config.REPO_DIR)

    Returns:
        TemplateData si le parsing réussit, None sinon
    """
    repo_dir = repo_dir or REPO_DIR
    full_path = repo_dir / file_path

    if not full_path.exists():
        logger.warning("Fichier introuvable: %s", full_path)
        return None

    try:
        raw_content = full_path.read_bytes()
        content_hash = _compute_hash(raw_content)
        data = yaml.safe_load(raw_content.decode("utf-8", errors="replace"))
    except yaml.YAMLError as e:
        logger.warning("Erreur YAML dans %s: %s", file_path, e)
        return None
    except Exception as e:
        logger.warning("Erreur lecture %s: %s", file_path, e)
        return None

    if not isinstance(data, dict):
        logger.warning("Template invalide (pas un dict) : %s", file_path)
        return None

    # Champ obligatoire : id
    template_id = data.get("id")
    if not template_id:
        logger.warning("Template sans 'id' : %s", file_path)
        return None

    info = data.get("info", {}) or {}
    classification = _extract_classification(info)

    # Tags : peut être string CSV ou liste
    tags_raw = info.get("tags", "")
    if isinstance(tags_raw, list):
        tags = ",".join(str(t) for t in tags_raw)
    else:
        tags = str(tags_raw) if tags_raw else ""

    return TemplateData(
        template_id=str(template_id),
        name=str(info.get("name", "")),
        severity=str(info.get("severity", "unknown")).lower(),
        tags=tags,
        protocol=_detect_protocol(data, file_path),
        cve_id=classification["cve_id"],
        cwe_id=classification["cwe_id"],
        cvss_score=classification["cvss_score"],
        description=str(info.get("description", "")) if info.get("description") else None,
        file_path=file_path,
        content_hash=content_hash,
    )


def parse_templates(file_paths: list[str], repo_dir: Path | None = None) -> list[TemplateData]:
    """
    Parse une liste de fichiers templates.

    Les fichiers malformés sont loggés et ignorés (pas de crash).

    Args:
        file_paths: Liste de chemins relatifs dans le repo
        repo_dir:   Répertoire racine du repo

    Returns:
        Liste de TemplateData pour les fichiers parsés avec succès
    """
    results: list[TemplateData] = []
    errors = 0

    for fp in file_paths:
        template = parse_template(fp, repo_dir)
        if template:
            results.append(template)
        else:
            errors += 1

    logger.info(
        "Parsing terminé: %d templates OK, %d erreurs sur %d fichiers",
        len(results), errors, len(file_paths),
    )
    return results
