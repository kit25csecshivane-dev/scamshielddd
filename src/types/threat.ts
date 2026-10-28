export type ThreatCategory =
  | 'phishing_url'
  | 'credential_harvesting'
  | 'advance_fee_scam'
  | 'investment_fraud'
  | 'recruitment_scam'
  | 'urgency_extortion'
  | 'brand_impersonation'
  | 'legitimate'
  | 'unknown';

export type RiskBand = 'Low Risk' | 'Medium Risk' | 'High Risk' | 'Critical Risk' | 'Unknown';

export type IndicatorSeverity = 'critical' | 'high' | 'medium' | 'low' | 'neutral';

export interface DetectedIndicator {
  id: string;
  category: string;
  title: string;
  description: string;
  whyItMatters: string;
  severity: IndicatorSeverity;
  evidenceSnippet?: string;
  ruleType: 'lexical_url' | 'nlp_heuristic' | 'ml_feature' | 'structure';
}

export interface FeatureContribution {
  feature: string;
  weight: number;
  frequency: number;
  contribution: number;
  direction: 'threat' | 'benign';
  description: string;
}

export interface HighlightSpan {
  start: number;
  end: number;
  text: string;
  severity: IndicatorSeverity;
  label: string;
}

export interface UrlMetrics {
  originalUrl: string;
  normalizedUrl: string;
  protocol: string;
  hostname: string;
  domain: string;
  subdomains: string[];
  tld: string;
  tldRiskLevel: 'high' | 'medium' | 'low' | 'neutral';
  path: string;
  pathDepth: number;
  queryParamCount: number;
  isIpAddress: boolean;
  hasPunycode: boolean;
  hasAtSymbol: boolean;
  suspiciousTokensFound: string[];
  totalLength: number;
  dotsInHostname: number;
  hyphensInHostname: number;
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  inputType: 'auto' | 'url' | 'email' | 'sms' | 'social' | 'other';
  detectedType: 'url' | 'message';
  rawInput: string;
  sanitizedDisplay: string;
  riskScore: number; // 0 to 100
  riskBand: RiskBand;
  primaryCategory: ThreatCategory;
  categoryLabel: string;
  confidence: number | null; // 0.00 to 1.00 when supported, or null
  analysisMode: 'hybrid_ml_rules' | 'transparent_baseline';
  summary: string;
  detailedExplanation: string;
  differenceExplanation: string;
  indicators: DetectedIndicator[];
  topFeatureContributions: FeatureContribution[];
  urlMetrics?: UrlMetrics;
  recommendations: string[];
  limitations: string[];
  highlightSpans: HighlightSpan[];
  computationTimeMs: number;
}

export interface ModelInfo {
  modelName: string;
  version: string;
  algorithm: string;
  vectorizer: string;
  vocabularySize: number;
  trainedClasses: string[];
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    testSampleSize: number;
    falseNegativeRate: number;
  };
  baselineAvailable: boolean;
  scoringWeights: {
    mlTextWeight: number;
    lexicalRuleWeight: number;
    compoundContextMultiplier: number;
  };
}

export interface AnalysisHistoryItem {
  id: string;
  timestamp: string;
  preview: string;
  detectedType: 'url' | 'message';
  riskScore: number;
  riskBand: RiskBand;
  primaryCategory: ThreatCategory;
}

export interface AnalysisRequest {
  content: string;
  inputType?: 'auto' | 'url' | 'email' | 'sms' | 'social' | 'other';
  allowHistory?: boolean;
}

export interface FeedbackRequest {
  analysisId: string;
  userAssessment: 'accurate' | 'false_positive' | 'false_negative' | 'uncertain';
  comments?: string;
}
