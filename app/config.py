"""Central settings. Change thresholds and weights here."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Database (the env variable lets the tests use a throw-away database)
DB_URL = os.getenv("SENTINEL_DB_URL", f"sqlite:///{BASE_DIR / 'sentinel.db'}")

# Machine-learning files
DATASET_PATH = BASE_DIR / "app" / "data" / "training_data.csv"
MODEL_PATH = BASE_DIR / "ml_artifacts" / "model.joblib"
METRICS_PATH = BASE_DIR / "ml_artifacts" / "metrics.json"

# Risk decision thresholds (risk score is 0-100)
SUSPICIOUS_THRESHOLD = 35   # score >= 35  -> SUSPICIOUS
BLOCK_THRESHOLD = 65        # score >= 65  -> BLOCKED

# How rule score and ML score are blended
RULE_WEIGHT = 0.6
ML_WEIGHT = 0.4
# A very strong rule match can never be "diluted" below this share of its own score
RULE_FLOOR_FACTOR = 0.8

# Input limits and privacy
MAX_PROMPT_LENGTH = 4000
PREVIEW_LENGTH = 80   # only this many characters of a prompt are stored
