import re
from typing import Dict, Any, List

MESSAGE_PATTERNS = [
    {
        "id": "grp_credentials",
        "category": "Credential Harvesting",
        "threatCategory": "credential_harvesting",
        "title": "Credential or Multi-Factor Authentication (OTP) Solicitation",
        "whyItMatters": "Authentic institutions will never ask for your password, PIN, or one-time verification code via email, SMS, or phone.",
        "severity": "critical",
        "patterns": [
            {
                "regex": re.compile(r'\b(one[- ]time password|otp|verification code|security code|passcode|pin code|auth code)\b', re.IGNORECASE),
                "label": "MFA/OTP Token Request",
                "description": "Explicit request for a temporary authentication passcode or OTP token.",
                "weight": 35
            },
            {
                "regex": re.compile(r'\b(share (your )?(password|credentials|pin|passcode)|confirm (your )?password|enter (your )?password)\b', re.IGNORECASE),
                "label": "Direct Password Elicitation",
                "description": "Direct demand to provide or verify account passwords.",
                "weight": 40
            }
        ]
    },
    {
        "id": "grp_urgency_threats",
        "category": "Psychological Coercion",
        "threatCategory": "urgency_extortion",
        "title": "Manufactured Urgency and Account Sanction Threats",
        "whyItMatters": "Social engineers fabricate immediate deadlines and threaten account suspension to induce compliance without reflection.",
        "severity": "high",
        "patterns": [
            {
                "regex": re.compile(r'\b(within (?:24|12|48|2) hours|in (?:24|48) hours|immediate action (?:is )?required|act immediately|final notice|final warning|last warning|account will be (?:permanently )?(?:suspended|closed|terminated|locked|disabled))\b', re.IGNORECASE),
                "label": "Urgency & Account Termination Threat",
                "description": "Imminent threat of account restriction combined with severe time pressure.",
                "weight": 30
            },
            {
                "regex": re.compile(r'\b(unauthorized (?:access|transaction|login)|suspicious activity detected|unusual sign[- ]in|security compromise)\b', re.IGNORECASE),
                "label": "Fabricated Security Alert",
                "description": "Pretextual security incident claim used to induce anxiety.",
                "weight": 20
            }
        ]
    },
    {
        "id": "grp_advance_fee",
        "category": "Advance-Fee Fraud",
        "threatCategory": "advance_fee_scam",
        "title": "Advance-Fee and Untraceable Payment Demand",
        "whyItMatters": "Demanding payment via untraceable means (crypto, wire, gift cards) or claiming upfront fees for releasing larger funds is fraudulent.",
        "severity": "high",
        "patterns": [
            {
                "regex": re.compile(r'\b(processing fee|clearance fee|handling fee|registration fee|customs fee|administrative charge)\b', re.IGNORECASE),
                "label": "Upfront Clearance Fee",
                "description": "Demand for an upfront monetary charge prior to receiving a supposed benefit.",
                "weight": 30
            },
            {
                "regex": re.compile(r'\b(apple gift card|steam card|google play card|vanilla visa|western union|moneygram|wire transfer to)\b', re.IGNORECASE),
                "label": "Irreversible / Untraceable Payment Channel",
                "description": "Demand for payment using untraceable vouchers or non-reversible money transfers.",
                "weight": 35
            }
        ]
    },
    {
        "id": "grp_investment",
        "category": "Financial Scam",
        "threatCategory": "investment_fraud",
        "title": "Guaranteed Return & Risk-Free Investment Claims",
        "whyItMatters": "High returns paired with zero risk are the hallmark of Ponzi schemes and fraudulent trading platforms.",
        "severity": "high",
        "patterns": [
            {
                "regex": re.compile(r'\b(guaranteed (?:[0-9]+% )?(?:return|returns|profit|income|payout)|100% (?:risk[- ]free|guaranteed)|double your (?:money|bitcoin|crypto|investment))\b', re.IGNORECASE),
                "label": "Guaranteed Profit Assurance",
                "description": "Unrealistic promise of risk-free investment multiplication.",
                "weight": 35
            },
            {
                "regex": re.compile(r'\b(crypto (?:investment|trading bot|automated trading)|passive daily income|mining pool return|insider trading tip|send [0-9.]+ (?:btc|eth|sol))\b', re.IGNORECASE),
                "label": "Cryptocurrency Multiplication Scheme",
                "description": "Solicitation for cryptocurrency deposit into private or unverified schemes.",
                "weight": 25
            }
        ]
    },
    {
        "id": "grp_recruitment",
        "category": "Recruitment Fraud",
        "threatCategory": "recruitment_scam",
        "title": "Fake Job Offer & Unvetted Hiring Ploy",
        "whyItMatters": "Employment scams promise high pay for simple work, skip interviews, and demand upfront payments for supplies.",
        "severity": "high",
        "patterns": [
            {
                "regex": re.compile(r'\b(no interview needed|instant hiring|daily payout of \$[0-9]+|\$[0-9]{2,4}\/day for simple tasks|part[- ]time remote assistant)\b', re.IGNORECASE),
                "label": "Unrealistic Employment Compensation",
                "description": "Disproportionately high pay offered without standard credential verification.",
                "weight": 25
            },
            {
                "regex": re.compile(r'\b(?:pay for|purchase|buy) (?:your )?(?:background check|home office equipment|equipment|starter kit|training kit|id badge)\b', re.IGNORECASE),
                "label": "Equipment / Onboarding Fee Extraction",
                "description": "Candidate required to pay money upfront to receive employment materials.",
                "weight": 35
            },
            {
                "regex": re.compile(r'\b(contact our hr on telegram|message our recruiter on whatsapp|reach out to @[a-z0-9_]+ on telegram)\b', re.IGNORECASE),
                "label": "Off-Platform Recruiter Redirection",
                "description": "Routing applicants away from corporate domains to encrypted anonymous messaging apps.",
                "weight": 25
            }
        ]
    }
]

def analyze_message_heuristics(text: str) -> Dict[str, Any]:
    indicators = []
    highlight_spans = []
    category_scores: Dict[str, int] = {}
    total_score = 0
    activated_groups = set()

    for group in MESSAGE_PATTERNS:
        for pattern in group["patterns"]:
            match = pattern["regex"].search(text)
            if match:
                total_score += pattern["weight"]
                activated_groups.add(group["id"])
                cat = group["threatCategory"]
                category_scores[cat] = category_scores.get(cat, 0) + pattern["weight"]

                indicators.append({
                    "id": f"{group['id']}_{len(indicators)}",
                    "category": group["category"],
                    "title": pattern["label"],
                    "description": pattern["description"],
                    "whyItMatters": group["whyItMatters"],
                    "severity": group["severity"],
                    "evidenceSnippet": match.group(0),
                    "ruleType": "nlp_heuristic"
                })

                highlight_spans.append({
                    "start": match.start(),
                    "end": match.end(),
                    "text": match.group(0),
                    "severity": group["severity"],
                    "label": pattern["label"]
                })

    compound_triggers = []
    if "grp_credentials" in activated_groups and "grp_urgency_threats" in activated_groups:
        total_score += 20
        compound_triggers.append("Urgent Coercion + Credential/OTP Solicitation")
        indicators.append({
            "id": "compound_urgency_credentials",
            "category": "Compound Threat Pattern",
            "title": "High-Velocity Credential Theft Combination",
            "description": "Message pairs urgent sanctions with credential or OTP passcode requests.",
            "whyItMatters": "Signature of active account takeover attempting to intercept 2FA codes.",
            "severity": "critical",
            "ruleType": "structure"
        })

    if "grp_recruitment" in activated_groups and "grp_advance_fee" in activated_groups:
        total_score += 20
        compound_triggers.append("Recruitment Offer + Upfront Payment Demand")
        indicators.append({
            "id": "compound_recruitment_fee",
            "category": "Compound Threat Pattern",
            "title": "Employment Fee Extraction Combination",
            "description": "Unverified job offer accompanied by upfront equipment fee.",
            "whyItMatters": "Legitimate employers never charge candidates for equipment or background checks.",
            "severity": "critical",
            "ruleType": "structure"
        })

    # High-Yield Investment Scam Compound Booster
    inv_matches = sum(1 for p in MESSAGE_PATTERNS[3]["patterns"] if p["regex"].search(text))
    if inv_matches >= 2:
        total_score += 25
        compound_triggers.append("Multi-Claim Investment Fraud (Guaranteed Return + Zero Risk)")
        indicators.append({
            "id": "compound_investment_fraud",
            "category": "Compound Threat Pattern",
            "title": "High-Yield Investment Fraud (HYIP) Signature",
            "description": "Message pairs unrealistic guaranteed returns with risk-free assertions and cryptocurrency transfer lures.",
            "whyItMatters": "Financial markets never offer guaranteed zero-risk high returns. This combination is the textbook hallmark of Ponzi schemes.",
            "severity": "critical",
            "ruleType": "structure"
        })

    suggested_category = "unknown"
    if category_scores:
        suggested_category = max(category_scores.items(), key=lambda x: x[1])[0]

    return {
        "heuristic_score": min(100, max(0, total_score)),
        "indicators": indicators,
        "highlight_spans": highlight_spans,
        "suggested_category": suggested_category,
        "compound_triggers": compound_triggers
    }
