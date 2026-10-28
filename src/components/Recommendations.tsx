import React from 'react';
import { ShieldCheck, AlertOctagon, CheckSquare } from 'lucide-react';
import { RiskBand } from '../types/threat';

interface RecommendationsProps {
  recommendations: string[];
  limitations: string[];
  riskBand: RiskBand;
}

export const Recommendations: React.FC<RecommendationsProps> = ({
  recommendations,
  limitations,
  riskBand,
}) => {
  const isHighOrCrit = riskBand === 'High Risk' || riskBand === 'Critical Risk';

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
      {/* Safe Action Recommendations */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 backdrop-blur-sm">
        <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2 border-b border-slate-800/80 pb-3">
          <ShieldCheck className={`h-4 w-4 ${isHighOrCrit ? 'text-rose-400' : 'text-emerald-400'}`} />
          <span>Recommended Protective Protocols</span>
        </h3>

        <ul className="mt-4 space-y-2.5">
          {recommendations.map((rec, i) => (
            <li key={i} className="flex items-start gap-2.5 text-xs text-slate-300 leading-relaxed">
              <CheckSquare className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Model Scope & Known Limitations */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 backdrop-blur-sm">
        <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2 border-b border-slate-800/80 pb-3">
          <AlertOctagon className="h-4 w-4 text-amber-400" />
          <span>Analysis Scope & Limitations</span>
        </h3>

        <ul className="mt-4 space-y-2 text-xs text-slate-400 leading-relaxed list-disc list-inside">
          {limitations.map((lim, i) => (
            <li key={i} className="pl-1">
              <span>{lim}</span>
            </li>
          ))}
        </ul>

        <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-500">
          Disclaimer: PhishGuard is a defensive decision-support prototype. It does not replace enterprise Endpoint Detection and Response (EDR) or authoritative organizational DNS records.
        </div>
      </div>
    </div>
  );
};
