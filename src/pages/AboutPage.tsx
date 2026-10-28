import React from 'react';
import { Shield, Lock, FileCode2, Terminal, CheckCircle, Database } from 'lucide-react';

export const AboutPage: React.FC = () => {
  return (
    <div className="space-y-8 max-w-5xl mx-auto py-4">
      {/* Page Title */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
          <Shield className="h-4 w-4" />
          <span>PROJECT OVERVIEW & SPECIFICATIONS</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
          About PhishGuard
        </h1>
        <p className="mt-2 text-sm text-slate-400 leading-relaxed">
          Engineered as a production-minded web application based on the research project report: <em>“Phishing and Scam Detection Using an Explainable Threat Analyzer Tool.”</em>
        </p>
      </div>

      {/* Core Objectives */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <h2 className="text-lg font-bold text-white mb-3">Project Objectives & Scope</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-300">
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2">
            <div className="font-semibold text-cyan-300">1. Explainable Threat Triage</div>
            <p className="text-slate-400 leading-relaxed">
              Eliminate black-box mystery by providing understandable rationales, feature contributions, and empirical evidence for every classification.
            </p>
          </div>
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2">
            <div className="font-semibold text-cyan-300">2. Safe Air-Gapped URL Parsing</div>
            <p className="text-slate-400 leading-relaxed">
              Deconstruct complex URLs purely through lexical and mathematical evaluation without ever establishing external network requests or visiting malicious destinations.
            </p>
          </div>
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2">
            <div className="font-semibold text-cyan-300">3. Multi-Vector Scam Detection</div>
            <p className="text-slate-400 leading-relaxed">
              Diagnose phishing URLs, MFA/OTP harvesting, upfront-fee recruitment scams, crypto investment schemes, and brand impersonation.
            </p>
          </div>
          <div className="p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 space-y-2">
            <div className="font-semibold text-cyan-300">4. Transparent Machine Learning</div>
            <p className="text-slate-400 leading-relaxed">
              Implement reproducible TF-IDF vectorization and Logistic Regression pipelines with inspectable weights and zero hallucinated threat feeds.
            </p>
          </div>
        </div>
      </section>

      {/* Technology Stack & Architecture */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <FileCode2 className="h-5 w-5 text-cyan-400" />
          <span>Technology Stack</span>
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/50">
            <div className="font-semibold text-white">Frontend</div>
            <div className="text-cyan-400 font-mono mt-1">React 19 + TypeScript + Vite</div>
            <p className="text-[11px] text-slate-400 mt-1">Tailwind CSS, SVG gauges, responsive cybersecurity layout.</p>
          </div>
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/50">
            <div className="font-semibold text-white">Live AI Studio Server</div>
            <div className="text-cyan-400 font-mono mt-1">Node.js Express + TSX</div>
            <p className="text-[11px] text-slate-400 mt-1">Real-time REST API, sub-millisecond execution, zero external bottlenecks.</p>
          </div>
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/50">
            <div className="font-semibold text-white">Python Backend & ML</div>
            <div className="text-cyan-400 font-mono mt-1">FastAPI + Scikit-Learn</div>
            <p className="text-[11px] text-slate-400 mt-1">Located in /backend, complete with train.py, evaluate.py, and pytest suite.</p>
          </div>
        </div>
      </section>

      {/* Security & Privacy Commitment */}
      <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 backdrop-blur-sm">
        <h2 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
          <Lock className="h-5 w-5 text-emerald-400" />
          <span>Security & Privacy Protocol</span>
        </h2>
        <ul className="text-xs text-slate-300 space-y-2 leading-relaxed">
          <li className="flex items-start gap-2">
            <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <span><strong>Untrusted Input Handling:</strong> All submitted text and URLs are treated as hazardous payloads and sanitized against XSS injection before rendering.</span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <span><strong>Zero Outbound Network Probing:</strong> PhishGuard never pings, resolves, or opens target URLs, protecting users from malware drops and IP tracking pixels.</span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
            <span><strong>No Message Archiving:</strong> In accordance with project specifications, analysis history is disabled by default. If enabled locally, data resides solely in the user's browser.</span>
          </li>
        </ul>
      </section>
    </div>
  );
};
