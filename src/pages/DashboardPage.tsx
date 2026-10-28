import React, { useState } from 'react';
import { Shield, Sparkles, Layers, Terminal } from 'lucide-react';
import { AnalysisForm, InputMode } from '../components/AnalysisForm';
import { RiskScoreGauge } from '../components/RiskScoreGauge';
import { ThreatBanner } from '../components/ThreatBanner';
import { HighlightedText } from '../components/HighlightedText';
import { EvidencePanel } from '../components/EvidencePanel';
import { ModelContributions } from '../components/ModelContributions';
import { Recommendations } from '../components/Recommendations';
import { ReportActions } from '../components/ReportActions';
import { FeedbackModal } from '../components/FeedbackModal';
import { AnalysisHistoryItem, AnalysisResult } from '../types/threat';

interface DashboardPageProps {
  onSaveHistoryItem?: (item: AnalysisHistoryItem) => void;
  isHistoryEnabled: boolean;
  initialResult?: AnalysisResult | null;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  onSaveHistoryItem,
  isHistoryEnabled,
  initialResult = null,
}) => {
  const [content, setContent] = useState('');
  const [inputMode, setInputMode] = useState<InputMode>('auto');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(initialResult);
  const [isFeedbackOpen, setIsFeedbackOpen] = useState(false);

  // Sync if initialResult changes from history selection
  React.useEffect(() => {
    if (initialResult) {
      setResult(initialResult);
      setContent(initialResult.rawInput);
    }
  }, [initialResult]);

  const handleAnalyze = async () => {
    if (!content.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          content,
          inputType: inputMode,
          allowHistory: isHistoryEnabled,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Analysis failed with status ${response.status}`);
      }

      const data: AnalysisResult = await response.json();
      setResult(data);

      // Save to optional history if enabled
      if (isHistoryEnabled && onSaveHistoryItem) {
        onSaveHistoryItem({
          id: data.id,
          timestamp: data.timestamp,
          preview: data.sanitizedDisplay.substring(0, 120),
          detectedType: data.detectedType,
          riskScore: data.riskScore,
          riskBand: data.riskBand,
          primaryCategory: data.primaryCategory,
        });
      }

      // Smooth scroll to results
      setTimeout(() => {
        document.getElementById('analysis-results')?.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } catch (err: any) {
      console.error('Threat analysis failure:', err);
      setError(err.message || 'An error occurred while evaluating content.');
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setContent('');
    setError(null);
  };

  const handleReset = () => {
    setResult(null);
    setContent('');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="space-y-10">
      {/* Hero Landing Section */}
      <section className="text-center pt-4 pb-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/40 border border-cyan-800/40 text-cyan-400 text-xs font-medium mb-4">
          <Sparkles className="h-3.5 w-3.5" />
          <span>Explainable Threat Intelligence Architecture</span>
        </div>

        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-tight">
          Detect Threats. Understand Risks. <br className="hidden sm:inline" />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-sky-400">
            Stay Protected.
          </span>
        </h1>

        <p className="mt-4 text-sm sm:text-base text-slate-400 max-w-2xl mx-auto leading-relaxed">
          PhishGuard combines transparent TF-IDF logistic regression with deep lexical URL parsing and heuristic rule engines to diagnose phishing links, credential traps, and financial scam campaigns with clear, evidence-based reasoning.
        </p>
      </section>

      {/* Input Analyzer Form */}
      <section>
        <AnalysisForm
          content={content}
          setContent={setContent}
          inputMode={inputMode}
          setInputMode={setInputMode}
          onAnalyze={handleAnalyze}
          onClear={handleClear}
          loading={loading}
          error={error}
        />
      </section>

      {/* Analysis Results View */}
      {result && (
        <section id="analysis-results" className="space-y-6 pt-4 border-t border-slate-800/80">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              <Shield className="h-5 w-5 text-cyan-400" />
              <span>Threat Triage Assessment</span>
            </h2>
            <span className="font-mono text-xs text-slate-500">ID: {result.id}</span>
          </div>

          {/* Threat Banner */}
          <ThreatBanner
            category={result.primaryCategory}
            categoryLabel={result.categoryLabel}
            summary={result.summary}
            riskBand={result.riskBand}
            detectedType={result.detectedType}
            timestamp={result.timestamp}
          />

          {/* Gauge & Inspected Text Split */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1">
              <RiskScoreGauge
                score={result.riskScore}
                riskBand={result.riskBand}
                confidence={result.confidence}
                analysisMode={result.analysisMode}
                computationTimeMs={result.computationTimeMs}
              />
            </div>
            <div className="lg:col-span-2 flex flex-col justify-between">
              <HighlightedText
                text={result.sanitizedDisplay}
                spans={result.highlightSpans}
                isUrl={result.detectedType === 'url'}
              />
              <div className="mt-4 p-3 rounded-lg border border-slate-800 bg-slate-950/40 text-xs text-slate-400 flex items-center justify-between">
                <span>Modality: <strong className="text-slate-200 capitalize">{result.detectedType}</strong></span>
                <span>Length: <strong className="text-slate-200">{result.sanitizedDisplay.length} chars</strong></span>
                <span>Status: <strong className="text-cyan-400">Triage Complete</strong></span>
              </div>
            </div>
          </div>

          {/* Diagnostic Evidence Panel */}
          <EvidencePanel
            indicators={result.indicators}
            urlMetrics={result.urlMetrics}
            differenceExplanation={result.differenceExplanation}
          />

          {/* Model N-Gram Contributions */}
          <ModelContributions
            contributions={result.topFeatureContributions}
            analysisMode={result.analysisMode}
          />

          {/* Recommendations & Limitations */}
          <Recommendations
            recommendations={result.recommendations}
            limitations={result.limitations}
            riskBand={result.riskBand}
          />

          {/* Report Export & Feedback Actions */}
          <ReportActions
            result={result}
            onReset={handleReset}
            onOpenFeedback={() => setIsFeedbackOpen(true)}
          />

          {/* Feedback Modal */}
          <FeedbackModal
            analysisId={result.id}
            isOpen={isFeedbackOpen}
            onClose={() => setIsFeedbackOpen(false)}
          />
        </section>
      )}
    </div>
  );
};
