"""
Re-train the XGBoost model with the currently installed XGBoost version.

This solves the pickle compatibility issue between XGBoost versions.
The model is re-trained with the exact same hyperparameters and pipeline
from the original notebook:
  - SelectKBest(k=15) features
  - LabelEncoder on categoricals
  - StandardScaler normalization
  - XGBClassifier with tuned hyperparameters
"""

import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from soc_agent.config import MODEL_PATH, SELECTED_FEATURES

# NSL-KDD columns
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

print("=" * 60)
print("Re-training XGBoost model (compatible with current version)")
print("=" * 60)

# Load data
data_path = Path("data/KDDTrain+.txt")
if not data_path.exists():
    print(f"ERROR: {data_path} not found!")
    sys.exit(1)

df = pd.read_csv(str(data_path), header=None, names=NSL_KDD_COLUMNS)
print(f"Loaded {len(df)} rows")

# Binary labels (matching notebook)
df["attack"] = df["attack"].apply(lambda x: "normal" if x == "normal" else "attack")

# LabelEncode categoricals (matching notebook)
le = LabelEncoder()
for col in ["protocol_type", "service", "flag", "attack"]:
    df[col] = le.fit_transform(df[col])

# Train/test split (matching notebook exactly)
X = df.drop(["attack"], axis=1)
y = df["attack"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=43)

# Select 15 best features (matching notebook)
X_train = X_train[SELECTED_FEATURES]
X_test = X_test[SELECTED_FEATURES]

# StandardScaler (matching notebook)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train with the exact same hyperparameters from the notebook's GridSearchCV
print("Training XGBClassifier with tuned hyperparameters...")
model = XGBClassifier(
    colsample_bytree=0.5,
    learning_rate=0.1,
    max_depth=6,
    n_estimators=128,
    subsample=0.8,
    random_state=42,
)
model.fit(X_train_scaled, y_train)

# Evaluate
from sklearn.metrics import f1_score, accuracy_score
y_pred = model.predict(X_test_scaled)
acc = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
print(f"Test Accuracy: {acc:.4f}")
print(f"Test F1 Score: {f1:.4f}")

# Save (overwrite old pickle)
backup_path = MODEL_PATH.with_suffix(".pkl.bak")
if MODEL_PATH.exists():
    import shutil
    shutil.copy2(MODEL_PATH, backup_path)
    print(f"Backed up old model to: {backup_path}")

with open(MODEL_PATH, "wb") as f:
    pickle.dump(model, f)

print(f"Saved re-trained model to: {MODEL_PATH}")
print(f"File size: {MODEL_PATH.stat().st_size:,} bytes")

# Verify it loads correctly
with open(MODEL_PATH, "rb") as f:
    loaded = pickle.load(f)
y_verify = loaded.predict(X_test_scaled)
assert np.array_equal(y_pred, y_verify), "Verification FAILED!"
print("Verification: model loads and produces identical predictions OK")
print("=" * 60)
print("DONE!")
