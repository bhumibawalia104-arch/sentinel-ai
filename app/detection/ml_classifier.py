"""
Layer 2: Machine-learning classifier (TF-IDF + Logistic Regression).

TF-IDF turns text into numbers (which words/word-pairs matter).
Logistic Regression learns from our labeled examples which words point to which category.
The model is trained on first start-up if no saved model exists (takes about a second).
"""
import csv
import json

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from app import config
from app.detection.normalizer import normalize

LABELS = ["benign", "instruction_override", "system_prompt_extraction",
          "role_spoofing", "data_exfiltration", "encoded_obfuscation"]

_model = None   # loaded model lives here


def _load_dataset():
    with open(config.DATASET_PATH, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    # The same normalizer is used for training and prediction, so the model also sees decoded text.
    texts = [normalize(r["text"])["ml_text"] for r in rows]
    labels = [r["label"] for r in rows]
    return texts, labels


def train(save: bool = True) -> dict:
    """Train on 75% of the data, evaluate on the held-out 25%, save model + metrics."""
    global _model
    texts, labels = _load_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, stratify=labels, random_state=42)

    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)),
        ("clf", LogisticRegression(max_iter=2000, C=10, class_weight="balanced")),
    ])
    model.fit(x_train, y_train)
    predicted = model.predict(x_test)

    # Binary view: is the prompt malicious (any attack class) or benign?
    to_bin = lambda ys: ["benign" if y == "benign" else "malicious" for y in ys]
    yb_true, yb_pred = to_bin(y_test), to_bin(predicted)
    p, r, f, _ = precision_recall_fscore_support(yb_true, yb_pred, pos_label="malicious", average="binary", zero_division=0)

    metrics = {
        "train_size": len(x_train), "test_size": len(x_test),
        "multiclass_accuracy": round(accuracy_score(y_test, predicted), 3),
        "binary_accuracy": round(accuracy_score(yb_true, yb_pred), 3),
        "binary_precision": round(p, 3), "binary_recall": round(r, 3), "binary_f1": round(f, 3),
        "binary_confusion_matrix": {
            "labels": ["benign", "malicious"],
            "matrix": confusion_matrix(yb_true, yb_pred, labels=["benign", "malicious"]).tolist(),
        },
        "multiclass_confusion_matrix": {
            "labels": LABELS,
            "matrix": confusion_matrix(y_test, predicted, labels=LABELS).tolist(),
        },
        "note": "Small hand-written dataset: treat these numbers as a demo, not a security guarantee.",
    }
    _model = model
    if save:
        config.MODEL_PATH.parent.mkdir(exist_ok=True)
        joblib.dump(model, config.MODEL_PATH)
        config.METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def load_or_train() -> bool:
    """Called at server start-up. Returns True if the model is ready."""
    global _model
    try:
        if config.MODEL_PATH.exists():
            _model = joblib.load(config.MODEL_PATH)
        elif config.DATASET_PATH.exists():
            train()
        else:
            _model = None
    except Exception as exc:   # e.g. a model saved by another scikit-learn version
        print(f"[SENTINEL] Could not load model ({exc}); retraining.")
        try:
            train()
        except Exception as exc2:
            print(f"[SENTINEL] ML layer disabled: {exc2}")
            _model = None
    return _model is not None


def get_metrics():
    if config.METRICS_PATH.exists():
        return json.loads(config.METRICS_PATH.read_text(encoding="utf-8"))
    return None


def predict(ml_text: str) -> dict:
    """Returns the ML 'suspicion score' (0-1) and the per-category probabilities."""
    if _model is None:
        return {"available": False, "p_malicious": 0.0, "top_category": "benign", "probabilities": {}}
    probs = _model.predict_proba([ml_text])[0]
    by_label = dict(zip(_model.classes_, [float(p) for p in probs]))
    p_malicious = 1.0 - by_label.get("benign", 0.0)
    attacks = {k: v for k, v in by_label.items() if k != "benign"}
    top_attack = max(attacks, key=attacks.get) if attacks else "benign"
    return {"available": True, "p_malicious": p_malicious,
            "top_category": top_attack, "probabilities": by_label}
