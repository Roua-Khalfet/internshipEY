"""
LangChain Tool definitions for the SOC Copilot Agent.

Tools:
    1. predict_anomaly   — Run XGBoost ML pipeline on network flow features
    2. search_nuclei_kb  — Search the Nuclei vulnerability knowledge base
    3. get_nuclei_stats  — Get global KB statistics for context
"""

import json
import logging
import sqlite3
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from langchain_core.tools import tool

from soc_agent.config import (
    CATEGORICAL_FEATURES,
    DB_PATH,
    MODEL_PATH,
    NUMERIC_FEATURES,
    PIPELINE_FEATURES,
    TARGET_MAPPING,
)

logger = logging.getLogger(__name__)

# ── Lazy-loaded singleton ──────────────────────────────────────────
_pipeline = None


def _get_pipeline():
    """Lazy-load the scikit-learn Pipeline (preprocessor + XGBoost) from .pkl."""
    global _pipeline
    if _pipeline is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"XGBoost pipeline not found at {MODEL_PATH}. "
                "Ensure 'nsl_kdd_xgboost_pipeline.pkl' is in the project root."
            )
        _pipeline = joblib.load(MODEL_PATH)
        logger.info("Loaded XGBoost pipeline from %s", MODEL_PATH)
    return _pipeline


# ═══════════════════════════════════════════════════════════════════
# Tool 1: ML Anomaly Prediction
# ═══════════════════════════════════════════════════════════════════

# Default values for numeric features not commonly available in alerts
_NUMERIC_DEFAULTS = {f: 0 for f in NUMERIC_FEATURES}


@tool
def predict_anomaly(alert_json: str) -> str:
    """Run the XGBoost intrusion detection pipeline on network flow features
    to predict whether the traffic is normal or an attack.

    The pipeline includes built-in preprocessing (encoding + scaling).
    You only need to provide the raw feature values.

    Args:
        alert_json: A JSON string containing network flow features.
            Key features to include (at minimum):
            - protocol_type (str): e.g. "tcp", "udp", "icmp"
            - service (str): Network service, e.g. "http", "ftp", "smtp", "private"
            - flag (str): Connection status flag, e.g. "SF", "S0", "REJ"
            - duration (float): Connection duration in seconds
            - src_bytes (int): Bytes sent from source to destination
            - dst_bytes (int): Bytes sent from destination to source
            - count (int): Connections to same host in past 2 seconds
            - srv_count (int): Connections to same service in past 2 seconds
            - serror_rate (float): SYN error rate (0.0 to 1.0)
            - srv_serror_rate (float): Service SYN error rate (0.0 to 1.0)
            - rerror_rate (float): REJ error rate (0.0 to 1.0)
            - logged_in (int): 1 if successfully logged in, 0 otherwise
            - hot (int): Number of "hot" indicators
            - wrong_fragment (int): Number of wrong fragments
            - num_compromised (int): Number of compromised conditions
            Additional features (default to 0 if not provided):
            - land, urgent, num_failed_logins, root_shell, su_attempted,
              num_root, num_file_creations, num_shells, num_access_files,
              num_outbound_cmds, is_host_login, is_guest_login,
              srv_rerror_rate, same_srv_rate, diff_srv_rate,
              srv_diff_host_rate, dst_host_count, dst_host_srv_count,
              dst_host_same_srv_rate, dst_host_diff_srv_rate,
              dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
              dst_host_serror_rate, dst_host_srv_serror_rate,
              dst_host_rerror_rate, dst_host_srv_rerror_rate

    Returns:
        A structured analysis string containing the prediction (normal/attack),
        confidence score, and the top contributing features.
    """
    try:
        alert = json.loads(alert_json)
    except json.JSONDecodeError as e:
        return f"ERROR: Invalid JSON input — {e}"

    # Validate that categorical features are present (required)
    missing_cat = [f for f in CATEGORICAL_FEATURES if f not in alert]
    if missing_cat:
        return (
            f"ERROR: Missing required categorical features: {missing_cat}. "
            f"These must be provided: {CATEGORICAL_FEATURES}"
        )

    try:
        pipeline = _get_pipeline()

        # Build a single-row DataFrame with all 41 features
        row = {}
        for feat in CATEGORICAL_FEATURES:
            row[feat] = str(alert[feat])
        for feat in NUMERIC_FEATURES:
            row[feat] = float(alert.get(feat, _NUMERIC_DEFAULTS[feat]))

        df = pd.DataFrame([row], columns=PIPELINE_FEATURES)

        # Predict using the full pipeline (encoding + scaling + XGBoost)
        prediction = pipeline.predict(df)[0]
        proba = pipeline.predict_proba(df)[0]

        # Target mapping: 0 = normal, 1 = attack
        label = "ATTACK" if prediction == 1 else "NORMAL"
        confidence = float(max(proba)) * 100

        # Get feature importances from the XGBoost step inside the pipeline
        xgb_model = pipeline.named_steps["classifier"]
        importances = xgb_model.feature_importances_

        # Map importances back to feature names
        # After ColumnTransformer, feature order is: categoricals then numerics
        all_feature_names = CATEGORICAL_FEATURES + NUMERIC_FEATURES
        feature_importance_pairs = list(zip(all_feature_names, importances))
        feature_importance_pairs.sort(key=lambda x: x[1], reverse=True)
        top_features = feature_importance_pairs[:5]

        # Build structured response
        lines = [
            "=== ML PREDICTION RESULT ===",
            f"Prediction  : {label}",
            f"Confidence  : {confidence:.1f}%",
            f"Attack Prob : {proba[1]*100:.1f}%",
            f"Normal Prob : {proba[0]*100:.1f}%",
            "",
            "Top 5 Contributing Features:",
        ]
        for feat_name, importance in top_features:
            raw_value = alert.get(feat_name, 0)
            lines.append(f"  • {feat_name} = {raw_value} (importance: {importance:.4f})")

        # Add key alert metadata for context
        lines.extend([
            "",
            "Key Alert Values:",
            f"  • Protocol: {alert.get('protocol_type', 'N/A')}",
            f"  • Service: {alert.get('service', 'N/A')}",
            f"  • Flag: {alert.get('flag', 'N/A')}",
            f"  • Src Bytes: {alert.get('src_bytes', 'N/A')}",
            f"  • Dst Bytes: {alert.get('dst_bytes', 'N/A')}",
            f"  • Duration: {alert.get('duration', 'N/A')}s",
            f"  • SYN Error Rate: {alert.get('serror_rate', 'N/A')}",
        ])

        return "\n".join(lines)

    except Exception as e:
        logger.exception("ML prediction failed")
        return f"ERROR: ML prediction failed — {e}"


# ═══════════════════════════════════════════════════════════════════
# Tool 2: Nuclei Knowledge Base Search
# ═══════════════════════════════════════════════════════════════════

@tool
def search_nuclei_kb(query: str, search_type: str = "keyword") -> str:
    """Search the Nuclei vulnerability knowledge base for templates matching
    a query. Use this to find known CVEs, vulnerability templates, and
    threat intelligence related to a detected anomaly.

    Args:
        query: The search term. Can be a tag name, protocol, severity level,
            CVE ID, service name, or general keyword depending on search_type.
        search_type: The type of search to perform. Must be one of:
            - "keyword"  : Fuzzy search across name, description, tags, CVE ID
                           (best for general investigation)
            - "tag"      : Exact tag match (e.g. "rce", "sqli", "xss", "cve")
            - "protocol" : Filter by protocol (e.g. "http", "dns", "tcp", "network")
            - "severity" : Filter by severity level ("critical", "high", "medium", "low", "info")

    Returns:
        Formatted list of matching vulnerability templates with their
        template_id, name, severity, CVE, CVSS score, and description.
        Returns up to 10 results.
    """
    db_path = DB_PATH
    if not db_path.exists():
        return (
            "ERROR: Nuclei knowledge base not found. "
            "Run 'python scripts/run_pipeline.py' to build the database."
        )

    search_type = search_type.lower().strip()

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        if search_type == "tag":
            # Exact tag search (tag is stored as CSV in the 'tags' column)
            rows = conn.execute(
                """SELECT template_id, name, severity, cve_id, cwe_id,
                          cvss_score, description, protocol, tags
                   FROM templates
                   WHERE ',' || tags || ',' LIKE ?
                   ORDER BY
                       CASE severity
                           WHEN 'critical' THEN 1
                           WHEN 'high' THEN 2
                           WHEN 'medium' THEN 3
                           WHEN 'low' THEN 4
                           ELSE 5
                       END
                   LIMIT 10""",
                (f"%,{query.strip()},%",),
            ).fetchall()

        elif search_type == "protocol":
            rows = conn.execute(
                """SELECT template_id, name, severity, cve_id, cwe_id,
                          cvss_score, description, protocol, tags
                   FROM templates
                   WHERE protocol = ?
                   ORDER BY
                       CASE severity
                           WHEN 'critical' THEN 1
                           WHEN 'high' THEN 2
                           WHEN 'medium' THEN 3
                           WHEN 'low' THEN 4
                           ELSE 5
                       END
                   LIMIT 10""",
                (query.lower().strip(),),
            ).fetchall()

        elif search_type == "severity":
            rows = conn.execute(
                """SELECT template_id, name, severity, cve_id, cwe_id,
                          cvss_score, description, protocol, tags
                   FROM templates
                   WHERE severity = ?
                   ORDER BY name
                   LIMIT 10""",
                (query.lower().strip(),),
            ).fetchall()

        else:  # keyword — default
            pattern = f"%{query.strip()}%"
            rows = conn.execute(
                """SELECT template_id, name, severity, cve_id, cwe_id,
                          cvss_score, description, protocol, tags
                   FROM templates
                   WHERE name LIKE ?
                      OR description LIKE ?
                      OR tags LIKE ?
                      OR cve_id LIKE ?
                      OR template_id LIKE ?
                   ORDER BY
                       CASE severity
                           WHEN 'critical' THEN 1
                           WHEN 'high' THEN 2
                           WHEN 'medium' THEN 3
                           WHEN 'low' THEN 4
                           ELSE 5
                       END
                   LIMIT 10""",
                (pattern, pattern, pattern, pattern, pattern),
            ).fetchall()

        conn.close()

        if not rows:
            return (
                f"No Nuclei templates found for query='{query}' "
                f"(search_type='{search_type}'). "
                "Try broadening the search or using a different search_type."
            )

        # Format results
        lines = [
            "=== NUCLEI KB SEARCH RESULTS ===",
            f"Query: '{query}' | Type: {search_type} | Found: {len(rows)} result(s)",
            "",
        ]

        for i, row in enumerate(rows, 1):
            r = dict(row)
            lines.append(f"-- Result {i} " + "-" * 40)
            lines.append(f"  Template ID : {r['template_id']}")
            lines.append(f"  Name        : {r['name']}")
            lines.append(f"  Severity    : {r['severity'].upper()}")
            lines.append(f"  Protocol    : {r['protocol']}")
            if r.get("cve_id"):
                lines.append(f"  CVE         : {r['cve_id']}")
            if r.get("cwe_id"):
                lines.append(f"  CWE         : {r['cwe_id']}")
            if r.get("cvss_score"):
                lines.append(f"  CVSS Score  : {r['cvss_score']}")
            if r.get("tags"):
                lines.append(f"  Tags        : {r['tags']}")
            if r.get("description"):
                desc = r["description"][:300]
                if len(r["description"]) > 300:
                    desc += "..."
                lines.append(f"  Description : {desc}")
            lines.append("")

        return "\n".join(lines)

    except Exception as e:
        logger.exception("Nuclei KB search failed")
        return f"ERROR: Nuclei KB search failed — {e}"


# ═══════════════════════════════════════════════════════════════════
# Tool 3: Knowledge Base Statistics
# ═══════════════════════════════════════════════════════════════════

@tool
def get_nuclei_stats() -> str:
    """Get global statistics about the Nuclei vulnerability knowledge base.
    Use this to understand the scope and coverage of the threat intelligence
    database, including total template counts, severity distribution,
    protocol coverage, and trending tags.

    Returns:
        Formatted statistics summary of the Nuclei KB.
    """
    db_path = DB_PATH
    if not db_path.exists():
        return "ERROR: Nuclei knowledge base not found."

    try:
        # Import from the existing nuclei_kb package
        import sys
        sys.path.insert(0, str(db_path.parent.parent))
        from nuclei_kb.queries import get_stats

        stats = get_stats(db_path)

        lines = [
            "=== NUCLEI KB STATISTICS ===",
            f"Total Templates : {stats['total']:,}",
            f"New This Week   : {stats['new_this_week']}",
            "",
            "By Severity:",
        ]
        for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
            count = stats["by_severity"].get(sev, 0)
            if count:
                lines.append(f"  • {sev:10s} : {count:,}")

        lines.append("\nBy Protocol:")
        for proto, count in sorted(
            stats["by_protocol"].items(), key=lambda x: -x[1]
        )[:10]:
            lines.append(f"  • {proto:12s} : {count:,}")

        lines.append("\nTop 15 Tags:")
        for tag, count in stats["top_tags"][:15]:
            lines.append(f"  • {tag:20s} : {count:,}")

        return "\n".join(lines)

    except Exception as e:
        logger.exception("Failed to get Nuclei stats")
        return f"ERROR: Failed to get statistics — {e}"
