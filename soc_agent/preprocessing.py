"""
NSL-KDD Preprocessing Pipeline for the SOC Copilot Agent.

Reconstructs the exact preprocessing steps from the training notebook:
  1. LabelEncoder on categorical columns (protocol_type, service, flag)
  2. Select the 15 best features (via SelectKBest)
  3. StandardScaler normalization

The encoders and scaler are loaded from saved artifacts in data/preprocessors/.
If they don't exist, run:  python scripts/save_preprocessors.py
"""

import logging
import pickle
from pathlib import Path

import numpy as np

from soc_agent.config import (
    CATEGORICAL_COLUMNS,
    LABEL_ENCODERS_PATH,
    SCALER_PATH,
    SELECTED_FEATURES,
)

logger = logging.getLogger(__name__)

# ── Fallback LabelEncoder mappings ─────────────────────────────────
# These are the exact alphabetical orderings sklearn.LabelEncoder
# produces on the NSL-KDD training set. Used ONLY if saved encoders
# are not found (the saved ones from save_preprocessors.py are preferred).
FALLBACK_PROTOCOL_TYPE_MAP = {"icmp": 0, "tcp": 1, "udp": 2}

FALLBACK_FLAG_MAP = {
    "OTH": 0, "REJ": 1, "RSTO": 2, "RSTOS0": 3, "RSTR": 4,
    "S0": 5, "S1": 6, "S2": 7, "S3": 8, "SF": 9, "SH": 10,
}

FALLBACK_SERVICE_MAP = {
    "IRC": 0, "X11": 1, "Z39_50": 2, "aol": 3, "auth": 4,
    "bgp": 5, "courier": 6, "csnet_ns": 7, "ctf": 8, "daytime": 9,
    "discard": 10, "domain": 11, "domain_u": 12, "echo": 13,
    "eco_i": 14, "ecr_i": 15, "efs": 16, "exec": 17, "finger": 18,
    "ftp": 19, "ftp_data": 20, "gopher": 21, "harvest": 22,
    "hostnames": 23, "http": 24, "http_2784": 25, "http_443": 26,
    "http_8001": 27, "imap4": 28, "iso_tsap": 29, "klogin": 30,
    "kshell": 31, "ldap": 32, "link": 33, "login": 34, "mtp": 35,
    "name": 36, "netbios_dgm": 37, "netbios_ns": 38,
    "netbios_ssn": 39, "netstat": 40, "nnsp": 41, "nntp": 42,
    "ntp_u": 43, "other": 44, "pm_dump": 45, "pop_2": 46,
    "pop_3": 47, "printer": 48, "private": 49, "red_i": 50,
    "remote_job": 51, "rje": 52, "shell": 53, "smtp": 54,
    "sql_net": 55, "ssh": 56, "sunrpc": 57, "supdup": 58,
    "systat": 59, "telnet": 60, "tftp_u": 61, "tim_i": 62,
    "time": 63, "urh_i": 64, "urp_i": 65, "uucp": 66,
    "uucp_path": 67, "vmnet": 68, "whois": 69,
}

FALLBACK_ENCODERS = {
    "protocol_type": FALLBACK_PROTOCOL_TYPE_MAP,
    "service": FALLBACK_SERVICE_MAP,
    "flag": FALLBACK_FLAG_MAP,
}


class NSLKDDPreprocessor:
    """
    Preprocesses raw network alert dictionaries into feature vectors
    compatible with the trained XGBoost model.

    Usage:
        preprocessor = NSLKDDPreprocessor()
        features = preprocessor.transform(alert_dict)
        # features is a numpy array of shape (1, 15), ready for model.predict()
    """

    def __init__(self):
        self._label_encoders: dict[str, dict] | None = None
        self._scaler = None
        self._load_artifacts()

    def _load_artifacts(self):
        """Load saved preprocessor artifacts, or fall back to hardcoded values."""
        # ── Load LabelEncoders ─────────────────────────────────────
        if LABEL_ENCODERS_PATH.exists():
            with open(LABEL_ENCODERS_PATH, "rb") as f:
                self._label_encoders = pickle.load(f)
            logger.info("Loaded LabelEncoders from %s", LABEL_ENCODERS_PATH)
        else:
            self._label_encoders = FALLBACK_ENCODERS
            logger.warning(
                "LabelEncoder artifacts not found at %s. "
                "Using fallback mappings. Run 'python scripts/save_preprocessors.py' "
                "to generate exact artifacts.",
                LABEL_ENCODERS_PATH,
            )

        # ── Load StandardScaler ────────────────────────────────────
        if SCALER_PATH.exists():
            with open(SCALER_PATH, "rb") as f:
                self._scaler = pickle.load(f)
            logger.info("Loaded StandardScaler from %s", SCALER_PATH)
        else:
            self._scaler = None
            logger.warning(
                "StandardScaler not found at %s. "
                "Predictions will use UNSCALED features — accuracy may be reduced. "
                "Run 'python scripts/save_preprocessors.py' to generate the scaler.",
                SCALER_PATH,
            )

    def _encode_categorical(self, column: str, value: str) -> int:
        """Encode a single categorical value using the loaded or fallback mapping."""
        mapping = self._label_encoders[column]

        # Handle dict-style mapping (from our fallback or saved format)
        if isinstance(mapping, dict):
            if value in mapping:
                return mapping[value]
            logger.warning(
                "Unknown value '%s' for column '%s'. Using default=0.", value, column
            )
            return 0

        # Handle sklearn LabelEncoder object (from saved artifacts)
        try:
            return int(mapping.transform([value])[0])
        except (ValueError, KeyError):
            logger.warning(
                "Unknown value '%s' for column '%s'. Using default=0.", value, column
            )
            return 0

    def transform(self, alert: dict) -> np.ndarray:
        """
        Transform a raw alert dictionary into a model-ready feature vector.

        Args:
            alert: Dictionary with NSL-KDD feature names as keys.
                   Must contain at least the 15 selected features.
                   Categorical values (protocol_type, service, flag) should
                   be strings (e.g., "tcp", "http", "SF").

        Returns:
            numpy array of shape (1, 15) — ready for model.predict()

        Raises:
            KeyError: If a required feature is missing from the alert dict.
        """
        # Step 1: Extract features in the correct order & encode categoricals
        feature_values = []
        for feat in SELECTED_FEATURES:
            raw_value = alert.get(feat)
            if raw_value is None:
                raise KeyError(
                    f"Missing required feature '{feat}' in alert. "
                    f"Required features: {SELECTED_FEATURES}"
                )

            if feat in CATEGORICAL_COLUMNS:
                feature_values.append(self._encode_categorical(feat, str(raw_value)))
            else:
                feature_values.append(float(raw_value))

        # Step 2: Reshape to (1, 15)
        X = np.array(feature_values, dtype=np.float64).reshape(1, -1)

        # Step 3: Scale if scaler is available
        if self._scaler is not None:
            X = self._scaler.transform(X)
        else:
            logger.debug("Skipping StandardScaler (not loaded).")

        return X

    def get_feature_names(self) -> list[str]:
        """Return the ordered list of feature names the model expects."""
        return list(SELECTED_FEATURES)
