import { DetectedIndicator, HighlightSpan, UrlMetrics } from '../types/threat';

// High-abuse TLDs frequently seen in commodity disposable phishing
const HIGH_RISK_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'buzz', 'fit', 'icu',
  'work', 'surf', 'click', 'link', 'country', 'gdn', 'mom', 'rest', 'live'
]);

const LOW_RISK_TLDS = new Set(['gov', 'mil', 'edu', 'ac.uk']);

// Suspicious security & authentication keywords in URL path/params
const SUSPICIOUS_URL_TOKENS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'update',
  'banking', 'secure', 'account', 'wallet', 'claim', 'bonus', 'free',
  'confirm', 'password', 'support', 'auth', 'recover', 'security', 'billing',
  'invoice', 'portal', 'ebay', 'paypal', 'apple', 'microsoft', 'google', 'netflix',
  'amazon', 'chase', 'wellsfargo', 'metamask', 'binance'
];

export interface UrlAnalysisOutput {
  isUrl: boolean;
  metrics?: UrlMetrics;
  indicators: DetectedIndicator[];
  highlightSpans: HighlightSpan[];
  lexicalScore: number; // 0 to 100
}

/**
 * Checks if the text appears to be or contains a single primary URL.
 */
export function looksLikeUrl(text: string): boolean {
  const trimmed = text.trim();
  if (/^https?:\/\//i.test(trimmed)) return true;
  if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/i.test(trimmed) && !trimmed.includes(' ')) return true;
  if (/^(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/.test(trimmed)) return true;
  return false;
}

/**
 * Parse and perform pure lexical evaluation without making any network request.
 */
export function analyzeUrlLexical(rawInput: string): UrlAnalysisOutput {
  const trimmed = rawInput.trim();
  let candidate = trimmed;

  // Normalize protocol for parsing
  if (!/^https?:\/\//i.test(candidate)) {
    candidate = 'http://' + candidate;
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      isUrl: false,
      indicators: [],
      highlightSpans: [],
      lexicalScore: 0,
    };
  }

  const indicators: DetectedIndicator[] = [];
  const highlightSpans: HighlightSpan[] = [];
  let score = 0;

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;
  const search = parsed.search;
  const totalLength = trimmed.length;

  // 1. IP-address based host (RFC 1918 or public IPv4/IPv6)
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isHexOrOctalIp = /^0x[0-9a-f]+/i.test(hostname) || /^0[0-7]+/.test(hostname);
  const isIp = isIpv4 || isHexOrOctalIp;

  if (isIp) {
    score += 35;
    indicators.push({
      id: 'url_ip_hostname',
      category: 'Network Hostname Obfuscation',
      title: 'Direct IP Address Used as Hostname',
      description: `The URL uses a raw IP address (${hostname}) instead of a registered domain name.`,
      whyItMatters: 'Legitimate organizations use branded domain names. Direct IP addresses bypass domain reputation filters and are often used by temporary phishing kits.',
      severity: 'critical',
      evidenceSnippet: hostname,
      ruleType: 'lexical_url',
    });
    highlightSpans.push({
      start: trimmed.indexOf(hostname),
      end: trimmed.indexOf(hostname) + hostname.length,
      text: hostname,
      severity: 'critical',
      label: 'IP Host',
    });
  }

  // 2. Punycode / Internationalized Domain Name (Homograph Attack)
  const hasPunycode = hostname.includes('xn--');
  if (hasPunycode) {
    score += 30;
    indicators.push({
      id: 'url_punycode',
      category: 'Homograph Deception',
      title: 'Punycode Internationalized Domain (IDN)',
      description: `Contains the prefix 'xn--', which indicates non-ASCII Unicode characters encoded in the domain name.`,
      whyItMatters: 'Attackers use visual homoglyphs (e.g., Cyrillic "а" instead of Latin "a") to visually impersonate trusted domains like apple.com or paypal.com.',
      severity: 'high',
      evidenceSnippet: hostname,
      ruleType: 'lexical_url',
    });
    highlightSpans.push({
      start: trimmed.indexOf('xn--'),
      end: trimmed.indexOf('xn--') + 4,
      text: 'xn--',
      severity: 'high',
      label: 'IDN Homograph',
    });
  }

  // 3. Userinfo '@' symbol in URL
  const hasAtSymbol = trimmed.includes('@');
  if (hasAtSymbol) {
    score += 25;
    indicators.push({
      id: 'url_at_symbol',
      category: 'URL Redirection Obfuscation',
      title: 'Embedded Authentication Symbol (@)',
      description: 'The URL contains an "@" symbol in the authority component.',
      whyItMatters: 'Standard browsers interpret text before "@" as credentials, ignoring it and navigating to the host appearing AFTER "@", misleading users about the real destination.',
      severity: 'high',
      evidenceSnippet: '@',
      ruleType: 'lexical_url',
    });
    const atIdx = trimmed.indexOf('@');
    highlightSpans.push({
      start: atIdx,
      end: atIdx + 1,
      text: '@',
      severity: 'high',
      label: 'Auth Redirection Trap',
    });
  }

  // 4. Scheme check: HTTP vs HTTPS
  const protocol = parsed.protocol.replace(':', '').toLowerCase();
  if (protocol === 'http') {
    score += 15;
    indicators.push({
      id: 'url_insecure_http',
      category: 'Protocol Security',
      title: 'Insecure HTTP Transport Protocol',
      description: 'The URL uses unencrypted plaintext HTTP rather than HTTPS.',
      whyItMatters: 'Modern trustworthy authentication portals always require TLS/HTTPS to protect credentials from man-in-the-middle eavesdropping.',
      severity: 'medium',
      evidenceSnippet: 'http://',
      ruleType: 'structure',
    });
  } else if (protocol === 'https') {
    // Crucial requirement: Never treat HTTPS as proof of legitimacy
    indicators.push({
      id: 'url_https_disclaimer',
      category: 'Protocol Context',
      title: 'HTTPS Certificate Present (Does Not Guarantee Authenticity)',
      description: 'The connection is encrypted using HTTPS.',
      whyItMatters: 'Over 80% of modern phishing websites utilize free automated TLS certificates (e.g., Let\'s Encrypt). HTTPS only protects data in transit, not who receives it.',
      severity: 'neutral',
      evidenceSnippet: 'https://',
      ruleType: 'structure',
    });
  }

  // 5. Hostname dot and subdomain analysis
  const hostParts = hostname.split('.');
  const dotsInHostname = hostParts.length - 1;
  const tld = hostParts.length >= 2 ? hostParts[hostParts.length - 1] : '';
  const domain = hostParts.length >= 2 ? `${hostParts[hostParts.length - 2]}.${tld}` : hostname;
  const subdomains = hostParts.length > 2 ? hostParts.slice(0, hostParts.length - 2) : [];

  if (dotsInHostname >= 4) {
    score += 20;
    indicators.push({
      id: 'url_excessive_subdomains',
      category: 'Domain Masquerading',
      title: 'Excessive Subdomain Stacking',
      description: `Hostname contains ${dotsInHostname} dots and ${subdomains.length} subdomain tiers (${hostname}).`,
      whyItMatters: 'Attackers prepend trusted brand names (e.g., "paypal.com.account-update.xyz") as subdomains to trick mobile users where only the beginning of the URL is visible.',
      severity: 'high',
      evidenceSnippet: hostname,
      ruleType: 'lexical_url',
    });
  }

  // 6. Hyphen count in hostname
  const hyphensInHostname = (hostname.match(/-/g) || []).length;
  if (hyphensInHostname >= 3) {
    score += 15;
    indicators.push({
      id: 'url_excessive_hyphens',
      category: 'Hostname Structure',
      title: 'Suspicious Multi-Hyphen Domain Pattern',
      description: `Hostname contains ${hyphensInHostname} hyphens (${hostname}).`,
      whyItMatters: 'Multiple hyphenated words like "security-update-account-verification" are classic indicators of automated typosquatting and phishing domain generators.',
      severity: 'medium',
      evidenceSnippet: hostname,
      ruleType: 'lexical_url',
    });
  }

  // 7. High-risk TLD check
  let tldRiskLevel: 'high' | 'medium' | 'low' | 'neutral' = 'neutral';
  if (HIGH_RISK_TLDS.has(tld)) {
    tldRiskLevel = 'high';
    score += 20;
    indicators.push({
      id: 'url_high_risk_tld',
      category: 'Top-Level Domain Reputation',
      title: `High-Abuse Top-Level Domain (.${tld})`,
      description: `The domain uses the .${tld} top-level domain, known for low-cost registration and disproportionate fraud abuse.`,
      whyItMatters: 'Free or ultra-cheap TLDs allow threat actors to register disposable domains en masse without verified business identity.',
      severity: 'high',
      evidenceSnippet: `.${tld}`,
      ruleType: 'lexical_url',
    });
  } else if (LOW_RISK_TLDS.has(tld)) {
    tldRiskLevel = 'low';
    score = Math.max(0, score - 20); // Significant mitigation for verified government/academic TLD
    indicators.push({
      id: 'url_institutional_tld',
      category: 'Top-Level Domain Reputation',
      title: `Regulated Institutional TLD (.${tld})`,
      description: `The domain uses .${tld}, which requires strict government or academic identity accreditation.`,
      whyItMatters: 'Registrations under .gov, .edu, and .mil are tightly restricted to verified official entities and rarely host external phishing scripts.',
      severity: 'neutral',
      evidenceSnippet: `.${tld}`,
      ruleType: 'lexical_url',
    });
  }

  // 8. Total URL length
  if (totalLength > 100) {
    score += 18;
    indicators.push({
      id: 'url_excessive_length',
      category: 'URL Obfuscation',
      title: `Abnormally Long URL (${totalLength} characters)`,
      description: `URL length is significantly higher than standard web navigation targets.`,
      whyItMatters: 'Extended lengths are used to push the actual domain out of sight on mobile screens and wrap tracking or obfuscated redirect tokens.',
      severity: 'medium',
      ruleType: 'lexical_url',
    });
  } else if (totalLength > 75) {
    score += 10;
  }

  // 9. Path depth & suspicious tokens
  const pathSegments = pathname.split('/').filter(Boolean);
  const pathDepth = pathSegments.length;
  if (pathDepth >= 5) {
    score += 12;
    indicators.push({
      id: 'url_deep_path',
      category: 'Directory Structure',
      title: `Deep Path Directory Structure (${pathDepth} levels)`,
      description: `Path traverses ${pathDepth} directory layers.`,
      whyItMatters: 'Compromised websites frequently host hidden phishing kits in deeply nested subdirectories to evade webmaster detection.',
      severity: 'medium',
      ruleType: 'lexical_url',
    });
  }

  // 10. Suspicious tokens found in URL
  const lowerUrl = candidate.toLowerCase();
  const tokensFound: string[] = [];
  for (const token of SUSPICIOUS_URL_TOKENS) {
    // Check if token is present in path or subdomain
    if (lowerUrl.includes(token)) {
      tokensFound.push(token);
    }
  }

  if (tokensFound.length > 0) {
    // Check if tokens mimic brands or sensitive operations
    const sensitiveTokens = tokensFound.filter(t => 
      ['login', 'verify', 'wallet', 'password', 'banking', 'secure', 'claim'].includes(t)
    );
    if (sensitiveTokens.length >= 2) {
      score += 25;
      indicators.push({
        id: 'url_sensitive_tokens_cluster',
        category: 'Credential Bait Pattern',
        title: `Sensitive Action Keywords in URL: [${sensitiveTokens.join(', ')}]`,
        description: `URL contains multiple high-risk credential-harvesting keywords.`,
        whyItMatters: 'Legitimate services consolidate login routing; phishing URLs cluster tokens like "secure", "verify", and "login" to induce urgency and trust.',
        severity: 'high',
        evidenceSnippet: sensitiveTokens.join(', '),
        ruleType: 'lexical_url',
      });
    } else if (sensitiveTokens.length === 1) {
      score += 10;
    }
  }

  // 11. Open redirect / Opaque URL forwarding query params
  const queryParams = new URLSearchParams(parsed.search);
  const queryParamCount = Array.from(queryParams.keys()).length;
  const redirectKeys = ['redirect', 'url', 'next', 'goto', 'dest', 'target', 'return'];
  const foundRedirectKey = redirectKeys.find(key => queryParams.has(key));

  if (foundRedirectKey) {
    const targetValue = queryParams.get(foundRedirectKey) || '';
    score += 20;
    indicators.push({
      id: 'url_open_redirect_param',
      category: 'Redirection Vector',
      title: `Suspected Redirection Parameter ('${foundRedirectKey}')`,
      description: `URL has parameter '${foundRedirectKey}=' pointing to '${targetValue.substring(0, 40)}...'`,
      whyItMatters: 'Open redirects allow attackers to use trusted hostnames to bypass email filters before bouncing the victim to an attacker-controlled server.',
      severity: 'high',
      evidenceSnippet: `${foundRedirectKey}=${targetValue}`,
      ruleType: 'lexical_url',
    });
  }

  const normalizedUrl = parsed.toString();
  const clampedScore = Math.min(100, Math.max(0, score));

  return {
    isUrl: true,
    metrics: {
      originalUrl: trimmed,
      normalizedUrl,
      protocol,
      hostname,
      domain,
      subdomains,
      tld,
      tldRiskLevel,
      path: pathname,
      pathDepth,
      queryParamCount,
      isIpAddress: isIp,
      hasPunycode,
      hasAtSymbol,
      suspiciousTokensFound: tokensFound,
      totalLength,
      dotsInHostname,
      hyphensInHostname,
    },
    indicators,
    highlightSpans,
    lexicalScore: clampedScore,
  };
}
