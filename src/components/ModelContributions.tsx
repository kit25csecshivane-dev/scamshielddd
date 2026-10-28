import React from 'react';
import { Cpu, ArrowUpRight, ArrowDownRight, Terminal } from 'lucide-react';
import { FeatureContribution } from '../types/threat';

interface ModelContributionsProps {
  contributions: FeatureContribution[];
  analysisMode: string;
}

export const ModelContributions: React.FC<ModelContributionsProps> = ({
  contributions,
  analysisMode,
}) => {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 backdrop-blur-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            <span>TF-IDF & Logistic Regression Feature Contributions</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Statistical n-gram token weights pushing inference toward threat (+ weight) or benign (- weight)
          </p>
        </div>
        <div className="text-xs font-mono text-slate-400 self-start sm:self-auto">
          <span>Model: </span>
          <span className="text-cyan-400">LogReg-TFIDF-v1.4</span>
        </div>
      </div>

      {contributions.length === 0 ? (
        <div className="mt-4 p-4 text-xs text-slate-400 bg-slate-950/50 rounded-lg border border-slate-800">
          No calibrated vocabulary n-grams matched the input text. Model fell back to neutral prior logit intercept (-0.42).
        </div>
      ) : (
        <div className="mt-4 space-y-2">
          {contributions.map((feat, i) => {
            const isThreat = feat.direction === 'threat';
            return (
              <div
                key={`${feat.feature}_${i}`}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-lg border border-slate-800/80 bg-slate-950/50 text-xs"
              >
                <div className="flex items-center gap-2.5">
                  {isThreat ? (
                    <div className="flex h-6 w-6 items-center justify-center rounded bg-rose-950/50 text-rose-400 border border-rose-900/50">
                      <ArrowUpRight className="h-3.5 w-3.5" />
                    </div>
                  ) : (
                    <div className="flex h-6 w-6 items-center justify-center rounded bg-emerald-950/50 text-emerald-400 border border-emerald-900/50">
                      <ArrowDownRight className="h-3.5 w-3.5" />
                    </div>
                  )}

                  <div>
                    <div className="flex items-center gap-2">
                      <code className="font-mono font-semibold text-slate-200">
                        "{feat.feature}"
                      </code>
                      <span className="text-[11px] text-slate-400">
                        ({feat.frequency}x frequency)
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {feat.description}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 self-end sm:self-auto">
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400">Log-Odds Impact</div>
                    <div className={`font-mono text-xs font-bold ${isThreat ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {isThreat ? `+${feat.contribution}` : `${feat.contribution}`}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Model Transparency Note */}
      <div className="mt-4 flex items-center justify-between text-[11px] text-slate-400 pt-3 border-t border-slate-800/80">
        <div className="flex items-center gap-1.5">
          <Terminal className="h-3 w-3 text-cyan-400" />
          <span>Sublinear TF-IDF · L2 Penalty · Intercept: -0.420</span>
        </div>
        <span>Zero black-box hallucinations</span>
      </div>
    </div>
  );
};
