from typing import List, Optional, Literal
from pydantic import BaseModel, Field

ThreatCategory = Literal[
    'phishing_url',
    'credential_harvesting',
    'advance_fee_scam',
    'investment_fraud',
    'recruitment_scam',
    'urgency_extortion',
    'brand_impersonation',
    'legitimate',
    'unknown'
]

RiskBand = Literal['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk', 'Unknown']
IndicatorSeverity = Literal['critical', 'high', 'medium', 'low', 'neutral']

class AnalysisRequest(BaseModel):
    content: str = Field(..., max_length=25000, description="URL or message text to analyze")
    inputType: Optional[Literal['auto', 'url', 'email', 'sms', 'social', 'other']] = 'auto'
    allowHistory: Optional[bool] = False

class DetectedIndicator(BaseModel):
    id: str
    category: str
    title: str
    description: str
    whyItMatters: str
    severity: IndicatorSeverity
    evidenceSnippet: Optional[str] = None
    ruleType: Literal['lexical_url', 'nlp_heuristic', 'ml_feature', 'structure']

class FeatureContribution(BaseModel):
    feature: str
    weight: float
    frequency: int
    contribution: float
    direction: Literal['threat', 'benign']
    description: str

class HighlightSpan(BaseModel):
    start: int
    end: int
    text: str
    severity: IndicatorSeverity
    label: str

class UrlMetrics(BaseModel):
    originalUrl: str
    normalizedUrl: str
    protocol: str
    hostname: str
    domain: str
    subdomains: List[str]
    tld: str
    tldRiskLevel: Literal['high', 'medium', 'low', 'neutral']
    path: str
    pathDepth: int
    queryParamCount: int
    isIpAddress: bool
    hasPunycode: bool
    hasAtSymbol: bool
    suspiciousTokensFound: List[str]
    totalLength: int
    dotsInHostname: int
    hyphensInHostname: int

class AnalysisResponse(BaseModel):
    id: str
    timestamp: str
    inputType: str
    detectedType: Literal['url', 'message']
    rawInput: str
    sanitizedDisplay: str
    riskScore: int = Field(..., ge=0, le=100)
    riskBand: RiskBand
    primaryCategory: ThreatCategory
    categoryLabel: str
    confidence: Optional[float] = None
    analysisMode: Literal['hybrid_ml_rules', 'transparent_baseline']
    summary: str
    detailedExplanation: str
    differenceExplanation: str
    indicators: List[DetectedIndicator]
    topFeatureContributions: List[FeatureContribution]
    urlMetrics: Optional[UrlMetrics] = None
    recommendations: List[str]
    limitations: List[str]
    highlightSpans: List[HighlightSpan]
    computationTimeMs: int

class FeedbackRequest(BaseModel):
    analysisId: str
    userAssessment: Literal['accurate', 'false_positive', 'false_negative', 'uncertain']
    comments: Optional[str] = Field(None, max_length=500)

class FeedbackResponse(BaseModel):
    success: bool
    message: str
    recordId: str

class ModelMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1Score: float
    testSampleSize: int
    falseNegativeRate: float

class ScoringWeights(BaseModel):
    mlTextWeight: float
    lexicalRuleWeight: float
    compoundContextMultiplier: float

class ModelInfoResponse(BaseModel):
    modelName: str
    version: str
    algorithm: str
    vectorizer: str
    vocabularySize: int
    trainedClasses: List[str]
    metrics: ModelMetrics
    baselineAvailable: bool
    scoringWeights: ScoringWeights

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    mode: str
    timestamp: str
