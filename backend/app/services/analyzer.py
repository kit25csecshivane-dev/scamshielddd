import time
import datetime
import uuid
from typing import Dict, Any
from backend.app.services.url_engine import analyze_url_lexical, looks_like_url
from backend.app.services.message_engine import analyze_message_heuristics
from backend.app.services.ml_engine import run_ml_inference, MODEL_METADATA

def get_risk_band(score: int, is_unknown: bool = False) -> str:
    if is_unknown:
        return 'Unknown'
    if score <= 30:
        return 'Low Risk'
    if score <= 60:
        return 'Medium Risk'
    if score <= 80:
        return 'High Risk'
    return 'Critical Risk'

def get_category_label(cat: str) -> str:
    labels = {
        'phishing_url': 'Deceptive Phishing URL',
        'credential_harvesting': 'Credential & MFA Harvesting',
        'advance_fee_scam': 'Advance-Fee / 419 Scam',
        'investment_fraud': 'Guaranteed Return Investment Fraud',
        'recruitment_scam': 'Unverified Recruitment / Employment Scam',
        'urgency_extortion': 'Coercive Urgency & Account Extortion',
        'brand_impersonation': 'Brand / Organization Impersonation',
        'legitimate': 'Benign Communication',
        'unknown': 'Indeterminate / Insufficient Evidence'
    }
    return labels.get(cat, 'Indeterminate / Insufficient Evidence')

def analyze_content(content: str, input_type: str = 'auto') -> Dict[str, Any]:
    start_time = time.time()
    trimmed = content.strip()
    scan_id = f"scan_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if len(trimmed) < 3:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return {
            "id": scan_id,
            "timestamp": timestamp,
            "inputType": input_type,
            "detectedType": "message",
            "rawInput": content,
            "sanitizedDisplay": trimmed or "[Empty Input]",
            "riskScore": 0,
            "riskBand": "Unknown",
            "primaryCategory": "unknown",
            "categoryLabel": get_category_label("unknown"),
            "confidence": None,
            "analysisMode": "transparent_baseline",
            "summary": "Insufficient content provided for diagnostic threat analysis.",
            "detailedExplanation": "Input contained fewer than 3 characters, falling below the minimum threshold required for analysis.",
            "differenceExplanation": "Detected Evidence consists of deterministic technical facts; Inferred Risk is a statistical estimation.",
            "indicators": [],
            "topFeatureContributions": [],
            "urlMetrics": None,
            "recommendations": ["Provide a complete URL or the full text of the suspicious message for analysis."],
            "limitations": [
                "URLs are analyzed solely based on structural and lexical features.",
                "Model is trained on representative data; novel zero-day attacks may evade detection.",
                "Tool acts as decision-support prototype."
            ],
            "highlightSpans": [],
            "computationTimeMs": max(1, elapsed_ms)
        }

    is_url = False
    if input_type == 'url':
        is_url = True
    elif input_type == 'auto':
        is_url = looks_like_url(trimmed)

    ml_res = run_ml_inference(trimmed)
    indicators = []
    highlight_spans = []
    url_metrics = None

    if is_url:
        url_res = analyze_url_lexical(trimmed)
        url_metrics = url_res["metrics"]
        indicators.extend(url_res["indicators"])
        highlight_spans.extend(url_res["highlight_spans"])

        lexical_score = url_res["lexical_score"]
        ml_score = ml_res["ml_score"]
        severe_bonus = 15 if any(i["severity"] == "critical" for i in url_res["indicators"]) else 0
        final_score = int(round(0.50 * lexical_score + 0.40 * ml_score + severe_bonus))
        primary_category = "phishing_url"

        if url_metrics and url_metrics["tldRiskLevel"] == "low" and lexical_score < 20:
            final_score = min(final_score, 15)
            primary_category = "legitimate"
    else:
        msg_res = analyze_message_heuristics(trimmed)
        indicators.extend(msg_res["indicators"])
        highlight_spans.extend(msg_res["highlight_spans"])

        heuristic_score = msg_res["heuristic_score"]
        ml_score = ml_res["ml_score"]
        compound_bonus = len(msg_res["compound_triggers"]) * 10
        final_score = int(round(0.45 * heuristic_score + 0.45 * ml_score + compound_bonus))

        if msg_res["suggested_category"] != "unknown":
            primary_category = msg_res["suggested_category"]
        elif final_score > 60:
            primary_category = "urgency_extortion"
        elif final_score <= 30:
            primary_category = "legitimate"
        else:
            primary_category = "unknown"

    final_score = min(100, max(0, final_score))
    risk_band = get_risk_band(final_score)
    confidence = round(0.50 + abs(final_score - 50) / 100.0, 2)

    # Recommendations
    recs = []
    if final_score > 60:
        if is_url:
            recs.append("Do NOT click or open the URL in any web browser.")
            recs.append("Report the URL to your security operations team or email provider.")
            recs.append("Navigate to legitimate services directly by typing their domain in a browser.")
        else:
            recs.append("Never share passwords, PINs, or One-Time Passwords (OTPs) with anyone.")
            recs.append("Do not reply or call back using the contact numbers provided.")
            recs.append("Verify through official, independently discovered contact channels.")
    elif final_score > 30:
        recs.append("Exercise caution before clicking any links or providing replies.")
        recs.append("Verify the sender's identity through an independent channel.")
    else:
        recs.append("No obvious malicious signals were identified in this sample.")
        recs.append("Notice: Low risk does not guarantee safety; remain vigilant with unexpected requests.")

    elapsed_ms = int((time.time() - start_time) * 1000)

    summary = f"{risk_band} ({final_score}/100): Identified as {get_category_label(primary_category)} with {len(indicators)} diagnostic indicator(s)."

    return {
        "id": scan_id,
        "timestamp": timestamp,
        "inputType": input_type,
        "detectedType": "url" if is_url else "message",
        "rawInput": content,
        "sanitizedDisplay": trimmed,
        "riskScore": final_score,
        "riskBand": risk_band,
        "primaryCategory": primary_category,
        "categoryLabel": get_category_label(primary_category),
        "confidence": confidence,
        "analysisMode": "hybrid_ml_rules",
        "summary": summary,
        "detailedExplanation": f"Analysis executed via combined lexical parsing and TF-IDF logistic regression. Observed {len(indicators)} structural indicator(s).",
        "differenceExplanation": "Detected Evidence consists of deterministic technical facts; Inferred Risk is a statistical estimation.",
        "indicators": indicators,
        "topFeatureContributions": ml_res["feature_contributions"][:8],
        "urlMetrics": url_metrics,
        "recommendations": recs,
        "limitations": [
            "URLs are analyzed solely based on structural and lexical features without network execution.",
            "Novel zero-day pretexts may evade detection.",
            "Tool acts as an explainable decision-support triage prototype."
        ],
        "highlightSpans": highlight_spans,
        "computationTimeMs": max(1, elapsed_ms)
    }
