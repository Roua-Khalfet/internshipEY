"""
Génération d'un rapport Markdown statique (alternative au dashboard Streamlit).

Usage:
    python scripts/generate_report.py
    python scripts/generate_report.py --output report.md
"""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nuclei_kb.queries import get_stats, get_new_templates_since, get_changes_this_week
from nuclei_kb.config import DB_PATH


def generate_report(output_path: str | None = None) -> str:
    """Génère un rapport Markdown et le retourne."""
    if not DB_PATH.exists():
        return "❌ Base de données non trouvée. Lance d'abord `python scripts/run_pipeline.py`"

    stats = get_stats()
    now = datetime.now(timezone.utc)
    week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")

    lines = [
        f"# 🛡️ Nuclei Templates — Rapport",
        f"",
        f"*Généré le {now.strftime('%Y-%m-%d %H:%M UTC')}*",
        f"",
        f"## 📊 Vue d'ensemble",
        f"",
        f"| Métrique | Valeur |",
        f"|----------|--------|",
        f"| Total templates | **{stats['total']:,}** |",
        f"| Nouveaux (7j) | **{stats['new_this_week']}** |",
        f"| Protocoles couverts | **{len(stats['by_protocol'])}** |",
        f"",
        f"## 🎯 Par sévérité",
        f"",
        f"| Sévérité | Nombre |",
        f"|----------|--------|",
    ]

    for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
        count = stats["by_severity"].get(sev, 0)
        if count:
            lines.append(f"| {sev} | {count:,} |")

    lines += [
        f"",
        f"## 🔌 Par protocole",
        f"",
        f"| Protocole | Nombre |",
        f"|-----------|--------|",
    ]

    for proto, count in sorted(stats["by_protocol"].items(), key=lambda x: -x[1]):
        lines.append(f"| {proto} | {count:,} |")

    lines += [
        f"",
        f"## 🏷️ Top 20 Tags",
        f"",
        f"| Tag | Nombre |",
        f"|-----|--------|",
    ]

    for tag, count in stats["top_tags"][:20]:
        lines.append(f"| `{tag}` | {count:,} |")

    # Nouveautés DNS/Network
    new_tpls = get_new_templates_since(week_ago)
    dns_net = [t for t in new_tpls if t.get("protocol") in ("dns", "network", "tcp")]

    lines += [
        f"",
        f"## 🆕 Nouveaux templates DNS/Network (7j)",
        f"",
    ]

    if dns_net:
        lines.append(f"| ID | Nom | Sévérité | Protocole | CVE |")
        lines.append(f"|----|-----|----------|-----------|-----|")
        for t in dns_net[:30]:
            lines.append(
                f"| `{t['template_id']}` | {t['name']} | {t['severity']} "
                f"| {t['protocol']} | {t.get('cve_id') or '-'} |"
            )
    else:
        lines.append("*Aucun nouveau template DNS/Network cette semaine.*")

    # Changements récents
    changes = get_changes_this_week()
    lines += [
        f"",
        f"## 📋 Changements récents (7j)",
        f"",
    ]

    if changes:
        lines.append(f"| Date | Template | Type |")
        lines.append(f"|------|----------|------|")
        for c in changes[:50]:
            lines.append(f"| {c['change_date']} | `{c['template_id']}` | {c['change_type']} |")
    else:
        lines.append("*Aucun changement cette semaine.*")

    report = "\n".join(lines)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")
        print(f"✅ Rapport généré : {output_path}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Générer un rapport Markdown")
    parser.add_argument("--output", "-o", default="data/report.md", help="Fichier de sortie")
    args = parser.parse_args()
    report = generate_report(args.output)
    if not args.output:
        print(report)


if __name__ == "__main__":
    main()
