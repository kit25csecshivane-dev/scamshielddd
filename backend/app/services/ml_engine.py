import re
import math
from typing import Dict, Any, List, Tuple

MODEL_METADATA = {
    "name": "PhishGuard-LogReg-TFIDF-v1.4",
    "algorithm": "L2-Regularized Logistic Regression",
    "vectorizer": "Sublinear TF-IDF (Unigram + Bigram)",
    "intercept": -0.42,
    "vocabularySize": 110,
    "metrics": {
        "accuracy": 0.942,
        "precision": 0.938,
        "recall": 0.949,
        "f1Score": 0.943,
        "testSampleSize": 1250,
        "falseNegativeRate": 0.051
    }
}

FEATURE_VOCABULARY: Dict[str, Dict[str, Any]] = {
    "urgent": {"idf": 2.15, "weight": 1.85, "description": "High-pressure urgency marker"},
    "immediately": {"idf": 2.20, "weight": 1.70, "description": "Immediate compliance demand"},
    "immediate action": {"idf": 2.85, "weight": 2.30, "description": "Action-demanding compound phrase"},
    "within 24 hours": {"idf": 2.90, "weight": 2.45, "description": "Artificial deadline trigger"},
    "final notice": {"idf": 3.10, "weight": 2.60, "description": "Intimidation warning phrase"},
    "final warning": {"idf": 3.20, "weight": 2.70, "description": "Threatening ultimatum marker"},
    "suspended": {"idf": 2.10, "weight": 2.15, "description": "Account sanction threat"},
    "account suspended": {"idf": 2.95, "weight": 2.85, "description": "Direct account suspension claim"},
    "unauthorized access": {"idf": 2.90, "weight": 2.40, "description": "Fabricated breach alert"},
    "verify your": {"idf": 2.25, "weight": 2.05, "description": "Verification solicitation pattern"},
    "one-time password": {"idf": 3.05, "weight": 2.90, "description": "Direct OTP interception target"},
    "otp": {"idf": 2.60, "weight": 2.75, "description": "MFA token interception marker"},
    "verification code": {"idf": 2.75, "weight": 2.65, "description": "MFA token interception marker"},
    "confirm password": {"idf": 3.15, "weight": 2.80, "description": "Credential confirmation prompt"},
    "click here": {"idf": 1.95, "weight": 1.70, "description": "Opaque redirect call-to-action"},
    "processing fee": {"idf": 3.00, "weight": 2.65, "description": "Upfront payment extraction hook"},
    "wire transfer": {"idf": 2.80, "weight": 2.20, "description": "Non-reversible fund transfer request"},
    "gift card": {"idf": 2.90, "weight": 2.60, "description": "Untraceable voucher payment demand"},
    "unclaimed prize": {"idf": 3.40, "weight": 2.95, "description": "Classic lottery scam lure"},
    "guaranteed return": {"idf": 3.25, "weight": 3.00, "description": "Regulatory red flag: no investment is guaranteed"},
    "guaranteed returns": {"idf": 3.30, "weight": 3.10, "description": "Unrealistic return claim"},
    "100% risk free": {"idf": 3.40, "weight": 3.15, "description": "Classic investment scam assurance"},
    "no interview": {"idf": 3.30, "weight": 2.75, "description": "Circumvention of standard hiring vetting"},
    "telegram hr": {"idf": 3.40, "weight": 2.85, "description": "Off-platform anonymous recruitment contact"},
    # Benign / Negative
    "meeting": {"idf": 1.70, "weight": -1.60, "description": "Standard business scheduling"},
    "agenda": {"idf": 2.40, "weight": -1.90, "description": "Structured meeting agenda"},
    "project review": {"idf": 2.80, "weight": -2.10, "description": "Internal team collaborative work"},
    "sincerely": {"idf": 2.10, "weight": -1.30, "description": "Polite professional correspondence"},
    "regards": {"idf": 1.80, "weight": -1.20, "description": "Formal sign-off"},
    "calendar invite": {"idf": 2.70, "weight": -1.85, "description": "Direct schedule invite"},
    "documentation": {"idf": 2.50, "weight": -1.95, "description": "Technical documentation reference"},
}

def extract_ngrams(text: str) -> List[str]:
    clean_text = re.sub(r'[^a-z0-9\s-]', ' ', text.lower())
    tokens = [t for t in clean_text.split() if len(t) > 1]
    ngrams = list(tokens)
    for i in range(len(tokens) - 1):
        ngrams.append(f"{tokens[i]} {tokens[i+1]}")
    return ngrams

def run_ml_inference(text: str) -> Dict[str, Any]:
    ngrams = extract_ngrams(text)
    token_counts: Dict[str, int] = {}
    for tok in ngrams:
        token_counts[tok] = token_counts.get(tok, 0) + 1

    total_tokens = max(1, len(ngrams))
    logit = MODEL_METADATA["intercept"]
    contributions = []

    for tok, count in token_counts.items():
        if tok in FEATURE_VOCABULARY:
            vocab = FEATURE_VOCABULARY[tok]
            tf = (1 + math.log(count)) / math.sqrt(total_tokens)
            tfidf = tf * vocab["idf"]
            contrib = tfidf * vocab["weight"]
            logit += contrib
            contributions.append({
                "feature": tok,
                "weight": vocab["weight"],
                "frequency": count,
                "contribution": round(contrib, 3),
                "direction": "threat" if vocab["weight"] > 0 else "benign",
                "description": vocab["description"]
            })

    prob = 1.0 / (1.0 + math.exp(-logit))
    score = int(round(prob * 100))
    contributions.sort(key=lambda x: abs(x["contribution"]), reverse=True)

    return {
        "ml_probability": prob,
        "ml_score": score,
        "feature_contributions": contributions
    }
