"""
Save Preprocessor Artifacts for the SOC Copilot Agent.

This script re-creates the exact preprocessing pipeline from the training
notebook and saves the LabelEncoders and StandardScaler to disk. These
artifacts are required for the SOC agent to make accurate predictions.

Usage:
    python scripts/save_preprocessors.py
    python scripts/save_preprocessors.py --data-path path/to/KDDTrain+.txt

If KDDTrain+.txt is not available locally, the script will download it
from the UCI ML Repository.
"""

import argparse
import logging
import pickle
import sys
import urllib.request
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

from soc_agent.config import (
    CATEGORICAL_COLUMNS,
    LABEL_ENCODERS_PATH,
    PREPROCESSORS_DIR,
    SCALER_PATH,
    SELECTED_FEATURES,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

# NSL-KDD column names (42 features + attack label + difficulty level)
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

DOWNLOAD_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
)


def find_or_download_data(data_path: str | None) -> Path:
    """Find KDDTrain+.txt locally or download it."""
    # Check common locations
    search_paths = [
        Path(data_path) if data_path else None,
        Path("KDDTrain+.txt"),
        Path("data/KDDTrain+.txt"),
        Path("models ipnyb/KDDTrain+.txt"),
    ]

    for p in search_paths:
        if p and p.exists():
            logger.info("✅ Found training data: %s", p)
            return p

    # Download if not found
    dest = Path("data/KDDTrain+.txt")
    logger.info("📥 Training data not found locally. Downloading from GitHub...")
    logger.info("   URL: %s", DOWNLOAD_URL)

    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(DOWNLOAD_URL, str(dest))
    logger.info("✅ Downloaded to: %s", dest)
    return dest


def main(data_path: str | None = None):
    """Re-create and save the preprocessing artifacts."""
    logger.info("=" * 60)
    logger.info("🔧 Saving Preprocessor Artifacts for SOC Copilot")
    logger.info("=" * 60)

    # ── Step 1: Load data ──────────────────────────────────────────
    data_file = find_or_download_data(data_path)
    logger.info("\n📂 Loading training data from: %s", data_file)

    df = pd.read_csv(str(data_file), header=None, names=NSL_KDD_COLUMNS)
    logger.info("   Loaded %d rows, %d columns", len(df), len(df.columns))

    # ── Step 2: Binary attack labeling (matching notebook) ─────────
    df["attack"] = df["attack"].apply(lambda x: "normal" if x == "normal" else "attack")

    # ── Step 3: LabelEncode categorical columns ────────────────────
    logger.info("\n🏷️  Fitting LabelEncoders on categorical columns...")

    # We encode all 4 columns (matching the notebook exactly)
    # but only save the 3 feature encoders (attack encoder is not needed for inference)
    all_encode_cols = ["protocol_type", "service", "flag", "attack"]
    label_encoders = {}

    for col in all_encode_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        if col != "attack":
            # Save as a simple dict for portability (no sklearn dependency at load time)
            label_encoders[col] = dict(zip(le.classes_, range(len(le.classes_))))
            logger.info(
                "   ✅ %s: %d unique values → %s",
                col,
                len(le.classes_),
                list(le.classes_[:5]),
            )

    # ── Step 4: Train/test split (matching notebook: test_size=0.1, random_state=43)
    from sklearn.model_selection import train_test_split

    X = df.drop(["attack"], axis=1)
    y = df["attack"]
    X_train, _, _, _ = train_test_split(X, y, test_size=0.1, random_state=43)

    # ── Step 5: Select the 15 best features ────────────────────────
    X_train_selected = X_train[SELECTED_FEATURES]
    logger.info(
        "\n📊 Selected %d features: %s", len(SELECTED_FEATURES), SELECTED_FEATURES
    )

    # ── Step 6: Fit StandardScaler ─────────────────────────────────
    logger.info("\n📐 Fitting StandardScaler on training data...")
    scaler = StandardScaler()
    scaler.fit(X_train_selected)

    logger.info("   Mean : %s", np.round(scaler.mean_, 4)[:5].tolist())
    logger.info("   Scale: %s", np.round(scaler.scale_, 4)[:5].tolist())

    # ── Step 7: Save artifacts ─────────────────────────────────────
    PREPROCESSORS_DIR.mkdir(parents=True, exist_ok=True)

    with open(LABEL_ENCODERS_PATH, "wb") as f:
        pickle.dump(label_encoders, f)
    logger.info("\n💾 Saved LabelEncoders → %s", LABEL_ENCODERS_PATH)

    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    logger.info("💾 Saved StandardScaler → %s", SCALER_PATH)

    # ── Verification ───────────────────────────────────────────────
    logger.info("\n🔍 Verification:")
    logger.info("   LabelEncoders file size: %d bytes", LABEL_ENCODERS_PATH.stat().st_size)
    logger.info("   StandardScaler file size: %d bytes", SCALER_PATH.stat().st_size)

    # Quick sanity check: encode a sample and verify shape
    sample = {
        "duration": 0, "protocol_type": 1, "service": 24, "flag": 9,
        "src_bytes": 491, "dst_bytes": 0, "wrong_fragment": 0, "hot": 0,
        "logged_in": 0, "num_compromised": 0, "count": 2, "srv_count": 2,
        "serror_rate": 0.0, "srv_serror_rate": 0.0, "rerror_rate": 0.0,
    }
    sample_array = np.array([sample[f] for f in SELECTED_FEATURES]).reshape(1, -1)
    scaled = scaler.transform(sample_array)
    logger.info("   Sample input shape: %s → Scaled output shape: %s ✅",
                sample_array.shape, scaled.shape)

    logger.info("\n" + "=" * 60)
    logger.info("✅ All preprocessor artifacts saved successfully!")
    logger.info("   You can now run: python scripts/run_soc_copilot.py")
    logger.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Save preprocessing artifacts for the SOC Copilot agent."
    )
    parser.add_argument(
        "--data-path",
        help="Path to KDDTrain+.txt (will download if not found)",
    )
    args = parser.parse_args()
    main(data_path=args.data_path)
