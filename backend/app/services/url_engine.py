import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'buzz', 'fit', 'icu',
    'work', 'surf', 'click', 'link', 'country', 'gdn', 'mom', 'rest', 'live'
}
LOW_RISK_TLDS = {'gov', 'mil', 'edu', 'ac.uk'}

SUSPICIOUS_URL_TOKENS = [
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'update',
    'banking', 'secure', 'account', 'wallet', 'claim', 'bonus', 'free',
    'confirm', 'password', 'support', 'auth', 'recover', 'security', 'billing',
    'invoice', 'portal', 'ebay', 'paypal', 'apple', 'microsoft', 'google', 'netflix',
    'amazon', 'chase', 'wellsfargo', 'metamask', 'binance'
]

def looks_like_url(text: str) -> bool:
    trimmed = text.strip()
    if re.match(r'^https?://', trimmed, re.IGNORECASE):
        return True
    if re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$', trimmed) and ' ' not in trimmed:
        return True
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$', trimmed):
        return True
    return False

def analyze_url_lexical(raw_input: str) -> Dict[str, Any]:
    trimmed = raw_input.strip()
    candidate = trimmed
    if not re.match(r'^https?://', candidate, re.IGNORECASE):
        candidate = 'http://' + candidate

    try:
        parsed = urlparse(candidate)
    except Exception:
        return {
            "is_url": False,
            "metrics": None,
            "indicators": [],
            "highlight_spans": [],
            "lexical_score": 0
        }

    indicators = []
    highlight_spans = []
    score = 0

    hostname = (parsed.hostname or '').lower()
    pathname = parsed.path or ''
    total_length = len(trimmed)

    # 1. IP Host
    is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
    if is_ip:
        score += 35
        indicators.append({
            "id": "url_ip_hostname",
            "category": "Network Hostname Obfuscation",
            "title": "Direct IP Address Used as Hostname",
            "description": f"The URL uses a raw IP address ({hostname}) instead of a registered domain name.",
            "whyItMatters": "Legitimate organizations use branded domain names. Direct IP addresses bypass domain reputation filters and are often used by temporary phishing kits.",
            "severity": "critical",
            "evidenceSnippet": hostname,
            "ruleType": "lexical_url"
        })
        start_idx = trimmed.find(hostname)
        if start_idx != -1:
            highlight_spans.append({
                "start": start_idx,
                "end": start_idx + len(hostname),
                "text": hostname,
                "severity": "critical",
                "label": "IP Host"
            })

    # 2. Punycode
    has_punycode = 'xn--' in hostname
    if has_punycode:
        score += 30
        indicators.append({
            "id": "url_punycode",
            "category": "Homograph Deception",
            "title": "Punycode Internationalized Domain (IDN)",
            "description": "Contains 'xn--', indicating non-ASCII Unicode characters encoded in the domain name.",
            "whyItMatters": "Attackers use visual homoglyphs (e.g. Cyrillic letters) to visually spoof trusted domains.",
            "severity": "high",
            "evidenceSnippet": hostname,
            "ruleType": "lexical_url"
        })

    # 3. Userinfo @ symbol
    has_at_symbol = '@' in trimmed
    if has_at_symbol:
        score += 25
        indicators.append({
            "id": "url_at_symbol",
            "category": "URL Redirection Obfuscation",
            "title": "Embedded Authentication Symbol (@)",
            "description": "URL contains an '@' symbol in the authority component.",
            "whyItMatters": "Browsers navigate to the host appearing AFTER the '@' symbol, deceiving users about the actual destination.",
            "severity": "high",
            "evidenceSnippet": "@",
            "ruleType": "lexical_url"
        })

    # 4. Scheme check
    protocol = parsed.scheme.lower()
    if protocol == 'http':
        score += 15
        indicators.append({
            "id": "url_insecure_http",
            "category": "Protocol Security",
            "title": "Insecure HTTP Transport Protocol",
            "description": "The URL uses unencrypted plaintext HTTP rather than HTTPS.",
            "whyItMatters": "Modern authentic websites always require HTTPS to safeguard user credentials.",
            "severity": "medium",
            "evidenceSnippet": "http://",
            "ruleType": "structure"
        })
    elif protocol == 'https':
        indicators.append({
            "id": "url_https_disclaimer",
            "category": "Protocol Context",
            "title": "HTTPS Certificate Present (Does Not Guarantee Authenticity)",
            "description": "The connection is encrypted using HTTPS.",
            "whyItMatters": "Over 80% of modern phishing websites utilize free automated TLS certificates. HTTPS only protects transit, not destination authenticity.",
            "severity": "neutral",
            "evidenceSnippet": "https://",
            "ruleType": "structure"
        })

    # 5. Hostname dot and subdomain analysis
    host_parts = hostname.split('.')
    dots_in_hostname = len(host_parts) - 1
    tld = host_parts[-1] if len(host_parts) >= 2 else ''
    domain = f"{host_parts[-2]}.{tld}" if len(host_parts) >= 2 else hostname
    subdomains = host_parts[:-2] if len(host_parts) > 2 else []

    if dots_in_hostname >= 4:
        score += 20
        indicators.append({
            "id": "url_excessive_subdomains",
            "category": "Domain Masquerading",
            "title": "Excessive Subdomain Stacking",
            "description": f"Hostname contains {dots_in_hostname} dots and {len(subdomains)} subdomain tiers ({hostname}).",
            "whyItMatters": "Attackers prepend brand names as subdomains to trick mobile browser address bars.",
            "severity": "high",
            "evidenceSnippet": hostname,
            "ruleType": "lexical_url"
        })

    hyphens_in_hostname = hostname.count('-')
    if hyphens_in_hostname >= 3:
        score += 15
        indicators.append({
            "id": "url_excessive_hyphens",
            "category": "Hostname Structure",
            "title": "Suspicious Multi-Hyphen Domain Pattern",
            "description": f"Hostname contains {hyphens_in_hostname} hyphens ({hostname}).",
            "whyItMatters": "Multiple hyphenated keywords are typical of typosquatting and automated phishing domain generators.",
            "severity": "medium",
            "evidenceSnippet": hostname,
            "ruleType": "lexical_url"
        })

    # TLD risk
    tld_risk_level = 'neutral'
    if tld in HIGH_RISK_TLDS:
        tld_risk_level = 'high'
        score += 20
        indicators.append({
            "id": "url_high_risk_tld",
            "category": "Top-Level Domain Reputation",
            "title": f"High-Abuse Top-Level Domain (.{tld})",
            "description": f"Domain uses .{tld}, recognized for low-cost registration and disproportionate fraud abuse.",
            "whyItMatters": "Disposable low-cost TLDs are frequently used for transient attack campaigns.",
            "severity": "high",
            "evidenceSnippet": f".{tld}",
            "ruleType": "lexical_url"
        })
    elif tld in LOW_RISK_TLDS:
        tld_risk_level = 'low'
        score = max(0, score - 20)
        indicators.append({
            "id": "url_institutional_tld",
            "category": "Top-Level Domain Reputation",
            "title": f"Regulated Institutional TLD (.{tld})",
            "description": f"Domain uses .{tld}, strictly restricted to verified government or educational institutions.",
            "whyItMatters": "Registrations under .gov/.edu require government/academic accreditation.",
            "severity": "neutral",
            "evidenceSnippet": f".{tld}",
            "ruleType": "lexical_url"
        })

    # Length
    if total_length > 100:
        score += 18
        indicators.append({
            "id": "url_excessive_length",
            "category": "URL Obfuscation",
            "title": f"Abnormally Long URL ({total_length} characters)",
            "description": "URL length is significantly elevated.",
            "whyItMatters": "Lengthy URLs push the true domain offscreen on mobile devices.",
            "severity": "medium",
            "ruleType": "lexical_url"
        })
    elif total_length > 75:
        score += 10

    # Path depth
    path_segments = [seg for seg in pathname.split('/') if seg]
    path_depth = len(path_segments)
    if path_depth >= 5:
        score += 12
        indicators.append({
            "id": "url_deep_path",
            "category": "Directory Structure",
            "title": f"Deep Path Directory Structure ({path_depth} levels)",
            "description": f"Path traverses {path_depth} nested folders.",
            "whyItMatters": "Phishing kits are frequently deployed inside deep directories on compromised servers.",
            "severity": "medium",
            "ruleType": "lexical_url"
        })

    # Tokens in URL
    lower_candidate = candidate.lower()
    tokens_found = [tok for tok in SUSPICIOUS_URL_TOKENS if tok in lower_candidate]
    sensitive_tokens = [tok for tok in tokens_found if tok in {'login', 'verify', 'wallet', 'password', 'banking', 'secure', 'claim'}]
    if len(sensitive_tokens) >= 2:
        score += 25
        indicators.append({
            "id": "url_sensitive_tokens_cluster",
            "category": "Credential Bait Pattern",
            "title": f"Sensitive Action Keywords in URL: [{', '.join(sensitive_tokens)}]",
            "description": "URL clusters multiple credential-harvesting tokens.",
            "whyItMatters": "Phishing URLs stack tokens like 'secure' and 'verify' to simulate authentic authentication portals.",
            "severity": "high",
            "evidenceSnippet": ", ".join(sensitive_tokens),
            "ruleType": "lexical_url"
        })
    elif len(sensitive_tokens) == 1:
        score += 10

    # Open redirect query params
    query_params = parse_qs(parsed.query)
    redirect_keys = ['redirect', 'url', 'next', 'goto', 'dest', 'target', 'return']
    found_redirect = next((k for k in redirect_keys if k in query_params), None)
    if found_redirect:
        score += 20
        target_val = query_params[found_redirect][0] if query_params[found_redirect] else ''
        indicators.append({
            "id": "url_open_redirect_param",
            "category": "Redirection Vector",
            "title": f"Suspected Redirection Parameter ('{found_redirect}')",
            "description": f"URL contains redirection key '{found_redirect}' pointing to '{target_val[:40]}...'",
            "whyItMatters": "Open redirects allow attackers to leverage trusted hosts to bounce victims to malicious sites.",
            "severity": "high",
            "evidenceSnippet": f"{found_redirect}={target_val}",
            "ruleType": "lexical_url"
        })

    clamped_score = min(100, max(0, score))

    metrics = {
        "originalUrl": trimmed,
        "normalizedUrl": parsed.geturl(),
        "protocol": protocol,
        "hostname": hostname,
        "domain": domain,
        "subdomains": subdomains,
        "tld": tld,
        "tldRiskLevel": tld_risk_level,
        "path": pathname,
        "pathDepth": path_depth,
        "queryParamCount": len(query_params),
        "isIpAddress": is_ip,
        "hasPunycode": has_punycode,
        "hasAtSymbol": has_at_symbol,
        "suspiciousTokensFound": tokens_found,
        "totalLength": total_length,
        "dotsInHostname": dots_in_hostname,
        "hyphensInHostname": hyphens_in_hostname
    }

    return {
        "is_url": True,
        "metrics": metrics,
        "indicators": indicators,
        "highlight_spans": highlight_spans,
        "lexical_score": clamped_score
    }
