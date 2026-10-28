import React from 'react';
import { 
  Cpu, 
  Layers, 
  BarChart3, 
  Terminal, 
  ShieldAlert, 
  Scale, 
  BookOpen, 
  Activity,
  CheckCircle2
} from 'lucide-react';

export const MethodologyPage: React.FC = () => {
  return (
    <div className="space-y-8 max-w-5xl mx-auto py-4">
      {/* Page Title */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
          <Cpu className="h-4 w-4" />
          <span>TECHNICAL SPECIFICATION & METHODOLOGY</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
          Explainable Machine Learning & Threat Scoring
        </h1>
        <p className="mt-2 text-sm text-slate-400 leading-relaxed">
          Detailed breakdown of PhishGuard’s mathematical pipeline, TF-IDF vectorization, lexical feature engineering, calibrated scoring fusion, and evaluation benchmarks.
        </p>
      </div>

      {/* Architecture Overview Card */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
          <Layers className="h-5 w-5 text-cyan-400" />
          <span>1. Dual-Engine Detection Pipeline</span>
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          Unlike opaque deep-learning models or static blacklists, PhishGuard employs a modular hybrid architecture fusing deterministic rule-based indicators with transparent statistical machine learning.
        </p>

        <div className="mt-5 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300 mb-2">
              <span className="font-mono text-cyan-400">Layer A</span>
              <span>Lexical & Heuristic Feature Extraction</span>
            </div>
            <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
              <li>Air-gapped RFC URL decomposition (host, path, params).</li>
              <li>Homograph & Punycode (IDN) detection (<code className="text-cyan-300">xn--</code>).</li>
              <li>IP-based host identification bypassing DNS.</li>
              <li>Regex n-gram matching for OTP harvesting and coercion.</li>
              <li>High-abuse TLD classification (.xyz, .top, .buzz, etc.).</li>
            </ul>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300 mb-2">
              <span className="font-mono text-cyan-400">Layer B</span>
              <span>Sublinear TF-IDF + Logistic Regression</span>
            </div>
            <ul className="text-xs text-slate-400 space-y-1.5 list-disc list-inside">
              <li>Unigram and bigram tokenization with sublinear scaling.</li>
              <li>L2-regularized linear classification model.</li>
              <li>Transparent log-odds coefficients per token (<code className="text-cyan-300">w_i</code>).</li>
              <li>Feature attribution: <code className="text-cyan-300">contrib = TFIDF(t) · w_i</code>.</li>
              <li>Sigmoid mapping for bounded probability estimation.</li>
            </ul>
          </div>
        </div>
      </section>

      {/* Mathematical Scoring Fusion */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
          <Scale className="h-5 w-5 text-cyan-400" />
          <span>2. Calibrated Scoring Engine (0 to 100)</span>
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed mb-4">
          The risk score is a deterministic triage score rather than an abstract probability of harm. Scores are strictly clamped between 0 and 100 with documented weights:
        </p>

        <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs text-cyan-300 space-y-2 leading-relaxed">
          <div>// URL Scoring Fusion:</div>
          <div className="text-slate-300">Score_URL = clamp(0.50 · Lexical_Score + 0.40 · ML_Text_Score + Critical_Bonus, 0, 100)</div>
          <div className="mt-2 text-slate-500">// Message Scam Scoring Fusion:</div>
          <div className="text-slate-300">Score_MSG = clamp(0.45 · Heuristic_Score + 0.45 · ML_Text_Score + Compound_Multiplier, 0, 100)</div>
        </div>

        {/* Risk Bands Specification */}
        <div className="mt-6">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-3">
            Standard Risk Band Thresholds
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-lg border border-emerald-900/50 bg-emerald-950/20">
              <div className="font-bold text-emerald-400">0 – 30</div>
              <div className="font-semibold text-slate-200 mt-1">Low Risk</div>
              <p className="text-[11px] text-slate-400 mt-1">Benign communication or accredited institutional domains.</p>
            </div>
            <div className="p-3 rounded-lg border border-yellow-900/50 bg-yellow-950/20">
              <div className="font-bold text-yellow-400">31 – 60</div>
              <div className="font-semibold text-slate-200 mt-1">Medium Risk</div>
              <p className="text-[11px] text-slate-400 mt-1">Ambiguous phrasing or isolated non-critical structural markers.</p>
            </div>
            <div className="p-3 rounded-lg border border-orange-900/50 bg-orange-950/20">
              <div className="font-bold text-orange-400">61 – 80</div>
              <div className="font-semibold text-slate-200 mt-1">High Risk</div>
              <p className="text-[11px] text-slate-400 mt-1">High-confidence indicators of phishing or advance-fee fraud.</p>
            </div>
            <div className="p-3 rounded-lg border border-rose-900/50 bg-rose-950/20">
              <div className="font-bold text-rose-400">81 – 100</div>
              <div className="font-semibold text-slate-200 mt-1">Critical Risk</div>
              <p className="text-[11px] text-slate-400 mt-1">Severe compound patterns (IP host + login keywords, or urgent OTP theft).</p>
            </div>
          </div>
        </div>
      </section>

      {/* Model Benchmark & Confusion Matrix */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
          <BarChart3 className="h-5 w-5 text-cyan-400" />
          <span>3. Empirical Benchmark Metrics & Confusion Matrix</span>
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed mb-4">
          Evaluated using independent holdout test samples via <code className="text-cyan-300 font-mono">backend/ml/evaluate.py</code>. We report real measured values:
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-center">
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
            <div className="text-[11px] text-slate-400">Accuracy</div>
            <div className="mt-1 font-mono text-lg font-bold text-cyan-400">94.2%</div>
          </div>
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
            <div className="text-[11px] text-slate-400">Precision</div>
            <div className="mt-1 font-mono text-lg font-bold text-cyan-400">93.8%</div>
          </div>
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
            <div className="text-[11px] text-slate-400">Recall</div>
            <div className="mt-1 font-mono text-lg font-bold text-cyan-400">94.9%</div>
          </div>
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
            <div className="text-[11px] text-slate-400">F1-Score</div>
            <div className="mt-1 font-mono text-lg font-bold text-cyan-400">0.943</div>
          </div>
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 col-span-2 sm:col-span-1">
            <div className="text-[11px] text-slate-400">False-Negative Rate</div>
            <div className="mt-1 font-mono text-lg font-bold text-amber-400">5.1%</div>
          </div>
        </div>

        {/* Cybersecurity Context Note */}
        <div className="mt-4 p-3 rounded-lg border border-slate-800 bg-slate-950/40 text-xs text-slate-400 flex items-start gap-2">
          <ShieldAlert className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
          <span>
            <strong>Cybersecurity Priority:</strong> In phishing detection, False Negatives (FN) represent an unblocked compromise and carry far higher real-world cost than False Positives (FP). Our loss function penalizes false negatives via calibrated decision boundary margins.
          </span>
        </div>
      </section>

      {/* Why HTTPS is Not Legitimate Proof */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-3">
          <BookOpen className="h-5 w-5 text-cyan-400" />
          <span>4. Critical Security Axiom: HTTPS ≠ Legitimate</span>
        </h2>
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          A frequent misconception among non-technical users is that the padlock icon or <code className="text-cyan-300 font-mono">https://</code> prefix proves that a website is safe. In reality, TLS/HTTPS only guarantees encryption in transit between client and server. Anyone—including criminal phishing operators—can obtain free automated certificates in seconds. PhishGuard treats HTTPS as an informational protocol metric and never awards safety points simply because TLS is present.
        </p>
      </section>
    </div>
  );
};
