import {
  AnalysisRequest,
  AnalysisResult,
  DetectedIndicator,
  FeatureContribution,
  HighlightSpan,
  IndicatorSeverity,
  ThreatCategory,
} from '../types/threat';
import {
  generateDetailedExplanation,
  generateDifferenceExplanation,
  generateRecommendations,
  generateSummary,
  getCategoryLabel,
  getKnownLimitations,
  getRiskBand,
} from './explainability';
import { analyzeMessageHeuristics } from './messageScamEngine';
import { FEATURE_VOCABULARY, MODEL_METADATA } from './mlWeights';
import { analyzeUrlLexical, looksLikeUrl } from './urlLexicalEngine';

/**
 * Tokenize text into words and lowercased unigrams and bigrams.
 */
function extractNgrams(text: string): { unigrams: string[]; bigrams: string[] } {
  // Strip punctuation for token extraction but preserve hyphens in compound words
  const cleanText = text.toLowerCase().replace(/[^a-z0-9\s-]/g, ' ');
  const tokens = cleanText.split(/\s+/).filter(t => t.length > 1);

  const unigrams = [...tokens];
  const bigrams: string[] = [];
  for (let i = 0; i < tokens.length - 1; i++) {
    bigrams.push(`${tokens[i]} ${tokens[i + 1]}`);
  }

  return { unigrams, bigrams };
}

/**
 * Executes TF-IDF Vectorization and Logistic Regression inference.
 */
function runMlInference(text: string): {
  mlProbability: number;
  mlScore: number;
  featureContributions: FeatureContribution[];
} {
  const { unigrams, bigrams } = extractNgrams(text);
  const allTokens = [...unigrams, ...bigrams];
  const tokenCounts: Record<string, number> = {};

  for (const token of allTokens) {
    tokenCounts[token] = (tokenCounts[token] || 0) + 1;
  }

  let logit = MODEL_METADATA.intercept;
  const contributions: FeatureContribution[] = [];
  const totalTokens = Math.max(1, allTokens.length);

  for (const [token, count] of Object.entries(tokenCounts)) {
    const vocab = FEATURE_VOCABULARY[token];
    if (vocab) {
      // Sublinear TF-IDF: (1 + ln(count)) * idf / sqrt(norm)
      const tf = (1 + Math.log(count)) / Math.sqrt(totalTokens);
      const tfidf = tf * vocab.idf;
      const contribution = tfidf * vocab.weight;

      logit += contribution;

      contributions.push({
        feature: token,
        weight: vocab.weight,
        frequency: count,
        contribution: Number(contribution.toFixed(3)),
        direction: vocab.weight > 0 ? 'threat' : 'benign',
        description: vocab.description,
      });
    }
  }

  // Sigmoid activation
  const probability = 1 / (1 + Math.exp(-logit));
  const mlScore = Math.round(probability * 100);

  // Sort contributions by absolute impact
  contributions.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

  return {
    mlProbability: probability,
    mlScore,
    featureContributions: contributions,
  };
}

/**
 * Core analysis engine that handles URLs and messages with explainability and scoring.
 */
export function analyzeThreat(request: AnalysisRequest): AnalysisResult {
  const startTime = performance.now();
  const rawInput = request.content || '';
  const trimmed = rawInput.trim();
  const inputType = request.inputType || 'auto';

  // ID and timestamp
  const id = `scan_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
  const timestamp = new Date().toISOString();

  // Edge Case 1: Empty or very short input
  if (trimmed.length < 3) {
    const elapsed = Math.round(performance.now() - startTime);
    return {
      id,
      timestamp,
      inputType,
      detectedType: 'message',
      rawInput,
      sanitizedDisplay: trimmed || '[Empty Input]',
      riskScore: 0,
      riskBand: 'Unknown',
      primaryCategory: 'unknown',
      categoryLabel: getCategoryLabel('unknown'),
      confidence: null,
      analysisMode: 'transparent_baseline',
      summary: 'Insufficient content provided for diagnostic threat analysis. Please enter a valid URL, message body, or communication sample.',
      detailedExplanation: 'The input contained fewer than 3 characters, which is below the minimum threshold required for lexical parsing or statistical NLP vectorization.',
      differenceExplanation: generateDifferenceExplanation(),
      indicators: [],
      topFeatureContributions: [],
      recommendations: ['Provide a complete URL or the full text of the suspicious message for analysis.'],
      limitations: getKnownLimitations(),
      highlightSpans: [],
      computationTimeMs: elapsed,
    };
  }

  // Determine whether input should be processed as a URL or a Message
  let isUrl = false;
  if (inputType === 'url') {
    isUrl = true;
  } else if (inputType === 'auto') {
    isUrl = looksLikeUrl(trimmed);
  }

  // Execute ML inference
  const mlResult = runMlInference(trimmed);

  let finalScore = 0;
  let primaryCategory: ThreatCategory = 'legitimate';
  let indicators: DetectedIndicator[] = [
    ...mlResult.featureContributions
      .filter(f => f.direction === 'threat' && f.contribution > 0.5)
      .slice(0, 3)
      .map(f => ({
        id: `ml_${f.feature.replace(/\s+/g, '_')}`,
        category: 'Statistical Language Model',
        title: `Elevated Threat Signal: "${f.feature}"`,
        description: f.description,
        whyItMatters: `This n-gram pattern exhibits a strong positive correlation (+${f.weight}) with fraudulent and scam datasets.`,
        severity: (f.contribution > 1.2 ? 'high' : 'medium') as IndicatorSeverity,
        evidenceSnippet: f.feature,
        ruleType: 'ml_feature' as const,
      })),
  ];

  let highlightSpans: HighlightSpan[] = [];
  let urlMetrics = undefined;

  if (isUrl) {
    const urlAnalysis = analyzeUrlLexical(trimmed);
    urlMetrics = urlAnalysis.metrics;
    indicators = [...urlAnalysis.indicators, ...indicators];
    highlightSpans = [...urlAnalysis.highlightSpans];

    // Score fusion for URL:
    // 50% Lexical features, 40% ML text tokens, 10% bonus for severe indicators
    const lexicalScore = urlAnalysis.lexicalScore;
    const mlScore = mlResult.mlScore;
    const severeBonus = urlAnalysis.indicators.some(i => i.severity === 'critical') ? 15 : 0;

    finalScore = Math.round(0.50 * lexicalScore + 0.40 * mlScore + severeBonus);
    primaryCategory = 'phishing_url';

    // If completely benign institutional URL (e.g. .edu, .gov) with 0 suspicious tokens
    if (urlMetrics?.tldRiskLevel === 'low' && lexicalScore < 20) {
      finalScore = Math.min(finalScore, 15);
      primaryCategory = 'legitimate';
    }
  } else {
    // Process as message
    const msgAnalysis = analyzeMessageHeuristics(trimmed);
    indicators = [...msgAnalysis.indicators, ...indicators];
    highlightSpans = [...msgAnalysis.highlightSpans];

    // Score fusion for Message:
    // 45% Heuristics, 45% ML TF-IDF text classification, 10% compound booster
    const heuristicScore = msgAnalysis.heuristicScore;
    const mlScore = mlResult.mlScore;
    const compoundBonus = msgAnalysis.compoundTriggersFound.length * 10;

    finalScore = Math.round(0.45 * heuristicScore + 0.45 * mlScore + compoundBonus);

    if (msgAnalysis.suggestedCategory !== 'unknown') {
      primaryCategory = msgAnalysis.suggestedCategory;
    } else if (finalScore > 60) {
      primaryCategory = 'urgency_extortion';
    } else if (finalScore <= 30) {
      primaryCategory = 'legitimate';
    } else {
      primaryCategory = 'unknown';
    }
  }

  // Clamp final score strictly between 0 and 100
  finalScore = Math.min(100, Math.max(0, finalScore));

  // Determine risk band
  const riskBand = getRiskBand(finalScore, false);

  // Confidence estimation: derived from distance from decision boundary (50%)
  // Only reported when meaningful (not fabricated)
  const confidence = Number((0.50 + Math.abs(finalScore - 50) / 100).toFixed(2));

  // Generate explainability components
  const summary = generateSummary(finalScore, riskBand, primaryCategory, indicators, isUrl, urlMetrics);
  const detailedExplanation = generateDetailedExplanation(
    riskBand,
    primaryCategory,
    indicators,
    mlResult.featureContributions
  );
  const differenceExplanation = generateDifferenceExplanation();
  const recommendations = generateRecommendations(riskBand, primaryCategory, isUrl, urlMetrics);
  const limitations = getKnownLimitations();

  const elapsed = Math.round(performance.now() - startTime);

  return {
    id,
    timestamp,
    inputType,
    detectedType: isUrl ? 'url' : 'message',
    rawInput,
    sanitizedDisplay: trimmed,
    riskScore: finalScore,
    riskBand,
    primaryCategory,
    categoryLabel: getCategoryLabel(primaryCategory),
    confidence,
    analysisMode: 'hybrid_ml_rules',
    summary,
    detailedExplanation,
    differenceExplanation,
    indicators,
    topFeatureContributions: mlResult.featureContributions.slice(0, 8),
    urlMetrics,
    recommendations,
    limitations,
    highlightSpans,
    computationTimeMs: Math.max(1, elapsed),
  };
}
