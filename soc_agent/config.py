"""
Centralized configuration for the SOC Copilot agent.
All paths are relative to the project root (BASE_DIR).
"""

import json
import os
from pathlib import Path

# ── Project Root ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent

# ── ML Model (scikit-learn Pipeline with XGBoost) ──────────────────
MODEL_PATH = BASE_DIR / "nsl_kdd_xgboost_pipeline.pkl"
METADATA_PATH = BASE_DIR / "nsl_kdd_xgboost_metadata.json"

# ── Nuclei Knowledge Base ──────────────────────────────────────────
DB_PATH = BASE_DIR / "data" / "nuclei_kb.db"

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    pass

# ── LLM Configuration ─────────────────────────────────────────────
NVIDIA_API_KEY_ENV = "NVIDIA_API_KEY"
NVIDIA_BASE_URL_DEFAULT = "https://integrate.api.nvidia.com/v1"
GROQ_API_KEY_ENV = "GROQ_API_KEY"
GEMINI_API_KEY_ENV = "GEMINI_API_KEY"

LLM_PROVIDER = os.environ.get(
    "LLM_PROVIDER",
    "nvidia"
    if os.environ.get("NVIDIA_API_KEY")
    else ("groq" if os.environ.get("GROQ_API_KEY") else "gemini"),
)

def _get_default_model(provider: str) -> str:
    if provider == "nvidia":
        return "google/diffusiongemma-26b-a4b-it"
    elif provider == "groq":
        return "llama-3.3-70b-versatile"
    return "gemini-3.8-flash"

LLM_MODEL_NAME = os.environ.get(
    "SOC_LLM_MODEL",
    _get_default_model(LLM_PROVIDER),
)

# ── NSL-KDD Feature Configuration ─────────────────────────────────
# From nsl_kdd_xgboost_metadata.json — the pipeline expects these features.

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]

NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

# All 41 features in the order the pipeline expects
PIPELINE_FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES

# Target mapping (from metadata)
TARGET_MAPPING = {"normal": 0, "attack": 1}
