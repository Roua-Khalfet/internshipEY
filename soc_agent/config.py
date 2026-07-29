"""
Centralized configuration for the SOC Copilot agent.
All paths are relative to the project root (BASE_DIR).
"""

import os
from pathlib import Path

# ── Project Root ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent

# ── ML Model ───────────────────────────────────────────────────────
MODEL_PATH = BASE_DIR / "xgboost_nsl_kdd.pkl"
PREPROCESSORS_DIR = BASE_DIR / "data" / "preprocessors"
SCALER_PATH = PREPROCESSORS_DIR / "standard_scaler.pkl"
LABEL_ENCODERS_PATH = PREPROCESSORS_DIR / "label_encoders.pkl"

# ── Nuclei Knowledge Base ──────────────────────────────────────────
DB_PATH = BASE_DIR / "data" / "nuclei_kb.db"

# ── LLM Configuration ─────────────────────────────────────────────
LLM_MODEL_NAME = os.environ.get("SOC_LLM_MODEL", "gemini-2.0-flash")
GEMINI_API_KEY_ENV = "GEMINI_API_KEY"
# Alternative: "GOOGLE_API_KEY" is also supported by langchain-google-genai

# ── NSL-KDD Feature Configuration ─────────────────────────────────
# The 42 original NSL-KDD column names (in order)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack", "level",
]

# The 15 features selected via SelectKBest (mutual_info_classif, k=15)
# These are the features the XGBoost model was trained on.
SELECTED_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "wrong_fragment", "hot", "logged_in", "num_compromised",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
]

# Categorical columns that were label-encoded in the notebook
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]
