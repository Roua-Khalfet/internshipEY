"""
Retrain the XGBoost pipeline locally so the .pkl file is compatible
with the current OS / Python / XGBoost / scikit-learn version.
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from xgboost import XGBClassifier
import warnings

warnings.filterwarnings("ignore")

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]

CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
NUMERIC_FEATURES = [c for c in COLUMN_NAMES if c not in CATEGORICAL_FEATURES + ["label", "difficulty"]]
PIPELINE_FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES

print("Loading dataset...")
df = pd.read_csv("KDDTrain+.txt", header=None, names=COLUMN_NAMES)
print(f"  Loaded {len(df)} rows")

# Create binary target (normal=0, attack=1)
df["target"] = (df["label"] != "normal").astype(int)
print(f"  Normal: {(df['target']==0).sum()}, Attack: {(df['target']==1).sum()}")

X = df[PIPELINE_FEATURES]
y = df["target"]

# Preprocessor
preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1), CATEGORICAL_FEATURES),
        ("num", StandardScaler(), NUMERIC_FEATURES),
    ]
)

# XGBoost Classifier
xgb = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss",
)

# Pipeline
pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", xgb),
])

print("Training pipeline...")
pipeline.fit(X, y)

# Quick accuracy check
from sklearn.metrics import accuracy_score
preds = pipeline.predict(X)
print(f"  Train accuracy: {accuracy_score(y, preds)*100:.2f}%")

print("Saving pipeline...")
joblib.dump(pipeline, "nsl_kdd_xgboost_pipeline.pkl", compress=3)
print("Done! Saved to nsl_kdd_xgboost_pipeline.pkl")

# Verify it loads back
print("Verifying reload...")
p2 = joblib.load("nsl_kdd_xgboost_pipeline.pkl")
test_pred = p2.predict(X.head(1))[0]
print(f"  Reload OK, test prediction: {test_pred}")
