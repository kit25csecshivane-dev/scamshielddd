import React from 'react';
import { RiskBand } from '../types/threat';

interface RiskScoreGaugeProps {
  score: number;
  riskBand: RiskBand;
  confidence: number | null;
  analysisMode: string;
  computationTimeMs: number;
}

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({
  score,
  riskBand,
  confidence,
  analysisMode,
  computationTimeMs,
}) => {
  // SVG semi-circle calculation
  const radius = 80;
  const strokeWidth = 14;
  const circumference = Math.PI * radius; // Half-circle
  const isUnknown = riskBand === 'Unknown';

  const strokeDashoffset = isUnknown 
    ? circumference 
    : circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;

  const getColorClasses = (band: RiskBand) => {
    switch (band) {
      case 'Critical Risk':
        return {
          stroke: '#f43f5e', // rose-500
          text: 'text-rose-400',
          bg: 'bg-rose-950/20',
          border: 'border-rose-900/40',
          glow: 'drop-shadow-[0_0_12px_rgba(244,63,94,0.4)]',
        };
      case 'High Risk':
        return {
          stroke: '#f97316', // orange-500
          text: 'text-orange-400',
          bg: 'bg-orange-950/20',
          border: 'border-orange-900/40',
          glow: 'drop-shadow-[0_0_12px_rgba(249,115,22,0.4)]',
        };
      case 'Medium Risk':
        return {
          stroke: '#eab308', // yellow-500
          text: 'text-yellow-400',
          bg: 'bg-yellow-950/20',
          border: 'border-yellow-900/40',
          glow: 'drop-shadow-[0_0_12px_rgba(234,179,8,0.3)]',
        };
      case 'Low Risk':
        return {
          stroke: '#10b981', // emerald-500
          text: 'text-emerald-400',
          bg: 'bg-emerald-950/20',
          border: 'border-emerald-900/40',
          glow: 'drop-shadow-[0_0_12px_rgba(16,185,129,0.3)]',
        };
      case 'Unknown':
      default:
        return {
          stroke: '#64748b', // slate-500
          text: 'text-slate-400',
          bg: 'bg-slate-900/30',
          border: 'border-slate-800',
          glow: '',
        };
    }
  };

  const style = getColorClasses(riskBand);

  return (
    <div className={`flex flex-col items-center justify-center p-6 rounded-xl border ${style.border} ${style.bg} bg-slate-900/50 backdrop-blur-sm transition-all duration-300`}>
      <div className="relative flex flex-col items-center justify-center">
        {/* Semi-circle Gauge SVG */}
        <svg
          width="210"
          height="125"
          viewBox="0 0 210 125"
          className={`overflow-visible ${style.glow}`}
        >
          {/* Background Arc */}
          <path
            d="M 25 105 A 80 80 0 0 1 185 105"
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Value Progress Arc */}
          <path
            d="M 25 105 A 80 80 0 0 1 185 105"
            fill="none"
            stroke={style.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score Display */}
        <div className="absolute top-10 flex flex-col items-center">
          <span className="font-mono text-4xl font-extrabold tracking-tight text-white">
            {isUnknown ? '—' : score}
          </span>
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
            {isUnknown ? 'Indeterminate' : '/ 100 Score'}
          </span>
        </div>
      </div>

      {/* Risk Band Label (No static pill, clean typography) */}
      <div className="mt-2 text-center">
        <h3 className={`text-lg font-bold tracking-tight ${style.text}`}>
          {riskBand}
        </h3>
        <p className="mt-0.5 text-xs text-slate-400">
          {isUnknown ? 'Evaluation inconclusive' : 'Threat Triage Assessment'}
        </p>
      </div>

      {/* Diagnostics Row */}
      <div className="mt-5 grid w-full grid-cols-2 divide-x divide-slate-800 border-t border-slate-800/80 pt-4 text-center">
        <div className="px-2">
          <div className="text-[11px] text-slate-400">Model Confidence</div>
          <div className="mt-0.5 font-mono text-xs font-semibold text-slate-200">
            {confidence !== null ? `${Math.round(confidence * 100)}%` : 'N/A'}
          </div>
        </div>
        <div className="px-2">
          <div className="text-[11px] text-slate-400">Processing Time</div>
          <div className="mt-0.5 font-mono text-xs font-semibold text-cyan-400">
            {computationTimeMs} ms
          </div>
        </div>
      </div>

      {/* Mode Note */}
      <div className="mt-3 flex items-center justify-center gap-1.5 text-[11px] text-slate-400">
        <span>Engine:</span>
        <span className="font-mono text-slate-300">
          {analysisMode === 'hybrid_ml_rules' ? 'TF-IDF + Rules Fusion' : 'Transparent Heuristics'}
        </span>
      </div>
    </div>
  );
};
