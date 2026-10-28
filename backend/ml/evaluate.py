"""
PhishGuard Model Evaluation Script
Computes Accuracy, Precision, Recall, F1-Score, Confusion Matrix,
and False-Negative Rate on an independent evaluation test dataset.
"""

import sys
import json
import argparse
from typing import List, Dict

from backend.ml.dataset import get_development_dataset
from backend.app.services.analyzer import analyze_content

def evaluate(dataset_path: str = None):
    print("=" * 65)
    print("   PhishGuard Threat Analyzer — Evaluation Report")
    print("=" * 65)

    samples: List[Dict[str, str]] = []
    if dataset_path:
        with open(dataset_path, "r", encoding="utf-8") as f:
            samples = json.load(f)
    else:
        print("[!] No separate test dataset provided. Evaluating on development suite.")
        print("[!] NOTICE: For real-world benchmark metrics, provide an independent test split.")
        samples = get_development_dataset()

    tp = 0  # True Positives: Predicted Threat, Actually Threat
    fp = 0  # False Positives: Predicted Threat, Actually Benign
    tn = 0  # True Negatives: Predicted Benign, Actually Benign
    fn = 0  # False Negatives: Predicted Benign, Actually Threat (CRITICAL in cybersecurity)

    print(f"[*] Processing {len(samples)} evaluation samples through PhishGuard Engine...\n")

    for i, s in enumerate(samples, 1):
        content = s["text"]
        actual_label = 1 if s["label"].lower() in ("phishing", "scam", "spam", "1") else 0

        result = analyze_content(content)
        # Threat predicted if risk score > 30 (Medium, High, or Critical risk)
        predicted_threat = 1 if result["riskScore"] > 30 else 0

        if actual_label == 1 and predicted_threat == 1:
            tp += 1
            status = "PASS (TP)"
        elif actual_label == 0 and predicted_threat == 0:
            tn += 1
            status = "PASS (TN)"
        elif actual_label == 0 and predicted_threat == 1:
            fp += 1
            status = "FAIL (FP)"
        else:
            fn += 1
            status = "FAIL (FN)"

        print(f"[{i:02d}] Actual: {'Threat' if actual_label else 'Benign':<6} | Pred Score: {result['riskScore']:>3}/100 ({result['riskBand']:<12}) | {status}")

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) else 0.0
    fnr = fn / (tp + fn) if (tp + fn) else 0.0

    print("\n" + "=" * 65)
    print("   Evaluation Summary & Confusion Matrix")
    print("=" * 65)
    print(f"  Total Samples Evaluated: {total}")
    print(f"  True Positives (TP):     {tp}")
    print(f"  True Negatives (TN):     {tn}")
    print(f"  False Positives (FP):    {fp}")
    print(f"  False Negatives (FN):    {fn}  <-- High priority in cybersecurity")
    print("-" * 65)
    print(f"  Accuracy:                {accuracy:.4f} ({accuracy*100:.1f}%)")
    print(f"  Precision:               {precision:.4f} ({precision*100:.1f}%)")
    print(f"  Recall (Sensitivity):    {recall:.4f} ({recall*100:.1f}%)")
    print(f"  F1-Score:                {f1:.4f}")
    print(f"  False-Negative Rate:     {fnr:.4f} ({fnr*100:.1f}%)")
    print("=" * 65)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_negative_rate": fnr,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn}
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate PhishGuard model")
    parser.add_argument("--test-data", type=str, default=None, help="Path to test dataset JSON")
    args = parser.parse_args()
    evaluate(args.test_data)
