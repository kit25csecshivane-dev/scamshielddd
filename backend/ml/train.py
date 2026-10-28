"""
PhishGuard Machine Learning Training Script
Fits TF-IDF vectorizer and Logistic Regression model on training corpus.
Saves model weights in JSON format for transparent and reproducible inference.
"""

import os
import json
import argparse
from typing import List, Dict

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from backend.ml.dataset import get_development_dataset

def train(dataset_path: str = None, output_path: str = "backend/ml/model_weights.json"):
    print("[*] Starting PhishGuard ML Model Training Pipeline...")

    samples: List[Dict[str, str]] = []
    if dataset_path and os.path.exists(dataset_path):
        print(f"[*] Loading custom dataset from: {dataset_path}")
        with open(dataset_path, "r", encoding="utf-8") as f:
            if dataset_path.endswith(".json"):
                samples = json.load(f)
            else:
                # Basic CSV format: text,label
                import csv
                reader = csv.DictReader(f)
                for row in reader:
                    samples.append({"text": row["text"], "label": row["label"]})
    else:
        print("[!] No custom dataset path provided or file missing. Using development fallback dataset.")
        print("[!] NOTE: Development dataset is intended for pipeline verification, not real-world benchmark assertions.")
        samples = get_development_dataset()

    texts = [s["text"] for s in samples]
    labels = [1 if s["label"].lower() in ("phishing", "spam", "scam", "1") else 0 for s in samples]

    if not SKLEARN_AVAILABLE:
        print("[!] scikit-learn is not installed in the current environment. Writing baseline weights.")
        weights_data = {
            "model_name": "PhishGuard-LogReg-TFIDF-Baseline",
            "intercept": -0.42,
            "vocabulary_size": len(texts),
            "status": "baseline_weights"
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(weights_data, f, indent=2)
        print(f"[+] Saved baseline weights to {output_path}")
        return

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=1,
        max_features=250
    )
    X = vectorizer.fit_transform(texts)
    y = labels

    model = LogisticRegression(C=1.0, max_iter=200, penalty="l2")
    model.fit(X, y)

    preds = model.predict(X)
    acc = accuracy_score(y, preds)
    prec = precision_score(y, preds, zero_division=0)
    rec = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)

    print(f"[+] Training complete. Samples: {len(texts)}")
    print(f"[+] Training Accuracy:  {acc:.4f}")
    print(f"[+] Training Precision: {prec:.4f}")
    print(f"[+] Training Recall:    {rec:.4f}")
    print(f"[+] Training F1-Score:  {f1:.4f}")

    # Export weights & vocabulary
    vocab = vectorizer.vocabulary_
    idfs = vectorizer.idf_
    coefs = model.coef_[0]

    feature_dict = {}
    for term, idx in vocab.items():
        feature_dict[term] = {
            "idf": round(float(idfs[idx]), 3),
            "weight": round(float(coefs[idx]), 3)
        }

    artifact = {
        "model_name": "PhishGuard-LogReg-TFIDF-Trained",
        "intercept": round(float(model.intercept_[0]), 3),
        "vocabulary_size": len(vocab),
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "sample_count": len(texts)
        },
        "features": feature_dict
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2)

    print(f"[+] Successfully exported model weights to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PhishGuard TF-IDF + Logistic Regression")
    parser.add_argument("--dataset", type=str, default=None, help="Path to labeled dataset (CSV/JSON)")
    parser.add_argument("--output", type=str, default="backend/ml/model_weights.json", help="Output path for weights")
    args = parser.parse_args()
    train(args.dataset, args.output)
