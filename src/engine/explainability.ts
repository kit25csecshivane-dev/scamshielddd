import { DetectedIndicator, FeatureContribution, RiskBand, ThreatCategory, UrlMetrics } from '../types/threat';

export function getRiskBand(score: number, isUnknown = false): RiskBand {
  if (isUnknown) return 'Unknown';
  if (score <= 30) return 'Low Risk';
  if (score <= 60) return 'Medium Risk';
  if (score <= 80) return 'High Risk';
  return 'Critical Risk';
}

export function getCategoryLabel(category: ThreatCategory): string {
  switch (category) {
    case 'phishing_url':
      return 'Deceptive Phishing URL';
    case 'credential_harvesting':
      return 'Credential & MFA Harvesting';
    case 'advance_fee_scam':
      return 'Advance-Fee / 419 Scam';
    case 'investment_fraud':
      return 'Guaranteed Return Investment Fraud';
    case 'recruitment_scam':
      return 'Unverified Recruitment / Employment Scam';
    case 'urgency_extortion':
      return 'Coercive Urgency & Account Extortion';
    case 'brand_impersonation':
      return 'Brand / Organization Impersonation';
    case 'legitimate':
      return 'Benign Communication';
    case 'unknown':
    default:
      return 'Indeterminate / Insufficient Evidence';
  }
}

export function generateSummary(
  riskScore: number,
  riskBand: RiskBand,
  category: ThreatCategory,
  indicators: DetectedIndicator[],
  isUrl: boolean,
  urlMetrics?: UrlMetrics
): string {
  if (riskBand === 'Unknown') {
    return 'The submitted content provides insufficient diagnostic signals or text volume for a reliable threat classification. No malicious indicators or benign patterns could be verified.';
  }

  const criticalCount = indicators.filter(i => i.severity === 'critical').length;
  const highCount = indicators.filter(i => i.severity === 'high').length;

  if (riskBand === 'Critical Risk') {
    if (isUrl && urlMetrics?.isIpAddress) {
      return `Critical threat detected: The submitted URL bypasses standard domain name registration by routing directly through a raw IP address (${urlMetrics.hostname}), exhibiting high-risk credential harvesting indicators.`;
    }
    return `Critical threat detected: Content exhibits ${criticalCount + highCount} severe threat signals matching high-probability social engineering and ${getCategoryLabel(category).toLowerCase()} patterns. Immediate defensive action is advised.`;
  }

  if (riskBand === 'High Risk') {
    return `Elevated risk detected: Analysis identified multiple high-confidence indicators consistent with ${getCategoryLabel(category).toLowerCase()}, including coercive urgency triggers and unverified origin characteristics.`;
  }

  if (riskBand === 'Medium Risk') {
    return `Moderate risk detected: While not exhibiting direct confirmed exploits, the content exhibits ambiguous phrasing or structural markers that warrant caution before clicking links or replying.`;
  }

  // Low Risk
  if (isUrl && urlMetrics?.tldRiskLevel === 'low') {
    return `Low risk profile: The URL resolves to an accredited institutional top-level domain (.${urlMetrics.tld}) with no deceptive subdomains or malicious redirect parameters detected.`;
  }
  return `Low risk profile: Content adheres to standard business or interpersonal communication conventions with no coercive urgency, credential solicitation, or fraudulent payment hooks detected.`;
}

export function generateDetailedExplanation(
  riskBand: RiskBand,
  category: ThreatCategory,
  indicators: DetectedIndicator[],
  features: FeatureContribution[]
): string {
  const topFeatures = features.filter(f => f.direction === 'threat').slice(0, 3).map(f => `"${f.feature}"`);
  const topBenign = features.filter(f => f.direction === 'benign').slice(0, 2).map(f => `"${f.feature}"`);

  let explanation = `This threat determination is established through an evidence-based fusion of lexical parsing, natural language heuristics, and statistical TF-IDF text classification.\n\n`;

  if (indicators.length > 0) {
    explanation += `Empirical Evidence: The analyzer observed ${indicators.length} observable structural or textual signal(s). `;
    const critList = indicators.filter(i => i.severity === 'critical' || i.severity === 'high');
    if (critList.length > 0) {
      explanation += `Key triggers include: ${critList.map(i => i.title).join('; ')}.\n\n`;
    } else {
      explanation += `All detected signals remain at mild or contextual severity.\n\n`;
    }
  }

  if (topFeatures.length > 0) {
    explanation += `Statistical Classifier Weights: The TF-IDF model identified token n-grams strongly associated with fraudulent campaigns, notably ${topFeatures.join(', ')}, which exerted significant positive log-odds weight.\n\n`;
  }

  if (topBenign.length > 0) {
    explanation += `Mitigating Factors: Benign conversational markers such as ${topBenign.join(', ')} attenuated the overall threat score.\n\n`;
  }

  return explanation;
}

export function generateDifferenceExplanation(): string {
  return `Methodological Distinction: "Detected Evidence" consists of deterministic, verifiable technical facts extracted directly from the input (such as an IP-based hostname, presence of an '@' symbol, or explicit demand for an OTP). In contrast, "Inferred Risk" is a probabilistic estimation of intent computed by machine learning weights and compound heuristic models. A high inferred score indicates that the observed pattern matches known attack profiles, but does not substitute for an authoritative DNS lookup or organization verification.`;
}

export function generateRecommendations(
  riskBand: RiskBand,
  category: ThreatCategory,
  isUrl: boolean,
  urlMetrics?: UrlMetrics
): string[] {
  const recs: string[] = [];

  if (riskBand === 'Critical Risk' || riskBand === 'High Risk') {
    if (isUrl) {
      recs.push('Do NOT click or open the URL in any web browser, and do NOT enter any credentials or personal data.');
      recs.push('If this link was received via email or message, do not reply to the sender; report the message to your organization’s security team or email provider as phishing.');
      recs.push('To reach the purported service, manually type their official, bookmarked domain name in a clean browser tab.');
    } else {
      recs.push('Never share passwords, PINs, or One-Time Passwords (OTPs) with anyone. Authentic organizations never solicit authentication codes.');
      recs.push('Do NOT call phone numbers or use Telegram/WhatsApp handles provided inside suspicious messages.');
      recs.push('If you already entered credentials or sent money, immediately change your account password and notify your bank or card issuer fraud department.');
    }

    if (category === 'recruitment_scam') {
      recs.push('Legitimate corporate employers conduct formal interviews and will never request you pay upfront for equipment or background checks.');
    }
    if (category === 'investment_fraud') {
      recs.push('Be aware that guaranteed high returns with zero risk do not exist in legitimate financial markets. Avoid sending cryptocurrency to unknown wallets.');
    }
  } else if (riskBand === 'Medium Risk') {
    recs.push('Exercise caution before interacting with this content or clicking any embedded links.');
    recs.push('Verify the identity of the sender through an independent, verified communication channel (such as an official phone number or website).');
    recs.push('Inspect the true destination address of any links before opening them.');
  } else {
    // Low risk
    recs.push('No obvious malicious signals were identified in this sample.');
    recs.push('Notice: A low-risk assessment does not guarantee complete safety. Modern targeted spear-phishing campaigns may use subtle or novel techniques.');
    recs.push('Always verify unexpected requests involving payments, wire transfers, or sensitive data through a secondary channel.');
  }

  return recs;
}

export function getKnownLimitations(): string[] {
  return [
    'Static Lexical Evaluation: URLs are analyzed solely based on their structural, lexical, and parameter characteristics. The tool intentionally does not establish network connections or render target web pages to prevent user exposure.',
    'Heuristic & Statistical Boundaries: The machine-learning classifier is trained on representative phishing, scam, and benign corpora; novel zero-day pretexts or carefully engineered human social engineering may evade detection (false negatives).',
    'Contextual Ambiguity: Legitimate IT security notices and billing reminders often use urgent phrasing (e.g., password expiration warnings), which may register elevated scores (potential false positives).',
    'Decision Support Tool: PhishGuard is designed as an explainable triage assistant and should not be used as the sole determinant for enterprise compliance or legal actions.',
  ];
}
