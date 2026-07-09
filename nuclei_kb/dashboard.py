"""
Composant 5 — Dashboard Streamlit pour la base nuclei-templates.

Lance avec : streamlit run nuclei_kb/dashboard.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from nuclei_kb.queries import (
    get_stats,
    get_new_templates_since,
    get_templates_by_protocol,
    get_templates_by_tag,
    get_changes_this_week,
    export_tag_list_for_nuclei_run,
)
from nuclei_kb.config import DB_PATH


# ── Page config ────────────────────────────────────────────────────

st.set_page_config(
    page_title="Nuclei Templates — Knowledge Base",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────

st.markdown("""
<style>
    .stMetric > div { background: linear-gradient(135deg, #1e1e2e, #2d2d44); 
        padding: 1rem; border-radius: 10px; border: 1px solid #44446688; }
    .stMetric label { color: #a0a0c0 !important; }
    .stMetric [data-testid="stMetricValue"] { color: #e0e0ff !important; }
</style>
""", unsafe_allow_html=True)


def main():
    st.title("🛡️ Nuclei Templates — Knowledge Base")
    st.caption("Base de connaissance auto-actualisée pour la détection réseau")

    if not DB_PATH.exists():
        st.error("⚠️ Base de données non trouvée. Lance d'abord `python scripts/run_pipeline.py`")
        return

    stats = get_stats()

    # ── KPIs ───────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📦 Total Templates", f"{stats['total']:,}")
    col2.metric("🆕 Nouveaux (7j)", stats["new_this_week"])
    col3.metric("🔌 Protocoles", len(stats["by_protocol"]))
    col4.metric("🏷️ Tags uniques", sum(c for _, c in stats["top_tags"]))

    st.divider()

    # ── Charts row ─────────────────────────────────────────────────
    chart_col1, chart_col2 = st.columns(2)

    # Sévérité
    with chart_col1:
        st.subheader("Répartition par sévérité")
        sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
        sev_colors = {
            "critical": "#ff4444", "high": "#ff8c00",
            "medium": "#ffd700", "low": "#4caf50",
            "info": "#2196f3", "unknown": "#9e9e9e",
        }
        sev_data = []
        for s in sev_order:
            if s in stats["by_severity"]:
                sev_data.append({"severity": s, "count": stats["by_severity"][s]})
        if sev_data:
            df_sev = pd.DataFrame(sev_data)
            fig_sev = px.bar(
                df_sev, x="severity", y="count",
                color="severity",
                color_discrete_map=sev_colors,
                text_auto=True,
            )
            fig_sev.update_layout(
                showlegend=False,
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#e0e0e0",
            )
            st.plotly_chart(fig_sev, use_container_width=True)

    # Protocoles
    with chart_col2:
        st.subheader("Répartition par protocole")
        if stats["by_protocol"]:
            df_proto = pd.DataFrame(
                list(stats["by_protocol"].items()),
                columns=["protocol", "count"],
            )
            fig_proto = px.pie(
                df_proto, names="protocol", values="count",
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Set2,
            )
            fig_proto.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#e0e0e0",
            )
            st.plotly_chart(fig_proto, use_container_width=True)

    # ── Top Tags ───────────────────────────────────────────────────
    st.subheader("🏷️ Top 20 Tags")
    if stats["top_tags"]:
        top20 = stats["top_tags"][:20]
        df_tags = pd.DataFrame(top20, columns=["tag", "count"])
        fig_tags = px.bar(
            df_tags, x="count", y="tag", orientation="h",
            color="count",
            color_continuous_scale="Viridis",
        )
        fig_tags.update_layout(
            yaxis=dict(autorange="reversed"),
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#e0e0e0",
            showlegend=False,
        )
        st.plotly_chart(fig_tags, use_container_width=True)

    st.divider()

    # ── Nouveautés DNS/Network de la semaine ───────────────────────
    st.subheader("🆕 Nouveaux templates DNS / Network (7 derniers jours)")
    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    new_templates = get_new_templates_since(week_ago)
    dns_network = [
        t for t in new_templates
        if t.get("protocol") in ("dns", "network", "tcp")
    ]
    if dns_network:
        df_new = pd.DataFrame(dns_network)[
            ["template_id", "name", "severity", "protocol", "tags", "cve_id"]
        ]
        st.dataframe(df_new, use_container_width=True, hide_index=True)
    else:
        st.info("Aucun nouveau template DNS/Network cette semaine")

    # ── Changements récents ────────────────────────────────────────
    st.subheader("📋 Historique des changements (7j)")
    changes = get_changes_this_week()
    if changes:
        df_ch = pd.DataFrame(changes)[["change_date", "template_id", "change_type"]]
        st.dataframe(df_ch, use_container_width=True, hide_index=True)
    else:
        st.info("Aucun changement enregistré cette semaine")

    st.divider()

    # ── Générateur de commande Nuclei ──────────────────────────────
    st.subheader("🚀 Générateur de commande Nuclei")
    available_tags = [t for t, _ in stats.get("top_tags", [])]
    selected = st.multiselect("Sélectionne les tags :", available_tags, default=[])
    if selected:
        cmd = export_tag_list_for_nuclei_run(selected)
        st.code(cmd, language="bash")
        st.caption("Copie cette commande pour lancer un scan ciblé")


if __name__ == "__main__":
    main()
