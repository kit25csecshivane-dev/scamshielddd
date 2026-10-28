import React from 'react';
import { 
  AlertTriangle, 
  CheckCircle, 
  HelpCircle, 
  Link2, 
  KeyRound, 
  DollarSign, 
  Briefcase, 
  TrendingUp, 
  ShieldAlert,
  Clock
} from 'lucide-react';
import { ThreatCategory, RiskBand } from '../types/threat';

interface ThreatBannerProps {
  category: ThreatCategory;
  categoryLabel: string;
  summary: string;
  riskBand: RiskBand;
  detectedType: 'url' | 'message';
  timestamp: string;
}

export const ThreatBanner: React.FC<ThreatBannerProps> = ({
  category,
  categoryLabel,
  summary,
  riskBand,
  detectedType,
  timestamp,
}) => {
  const getCategoryIcon = (cat: ThreatCategory) => {
    switch (cat) {
      case 'phishing_url':
        return <Link2 className="h-5 w-5 text-rose-400" />;
      case 'credential_harvesting':
        return <KeyRound className="h-5 w-5 text-rose-400" />;
      case 'advance_fee_scam':
        return <DollarSign className="h-5 w-5 text-orange-400" />;
      case 'investment_fraud':
        return <TrendingUp className="h-5 w-5 text-orange-400" />;
      case 'recruitment_scam':
        return <Briefcase className="h-5 w-5 text-amber-400" />;
      case 'urgency_extortion':
        return <AlertTriangle className="h-5 w-5 text-rose-400" />;
      case 'brand_impersonation':
        return <ShieldAlert className="h-5 w-5 text-yellow-400" />;
      case 'legitimate':
        return <CheckCircle className="h-5 w-5 text-emerald-400" />;
      case 'unknown':
      default:
        return <HelpCircle className="h-5 w-5 text-slate-400" />;
    }
  };

  const getBorderColor = (band: RiskBand) => {
    switch (band) {
      case 'Critical Risk':
        return 'border-rose-900/60 bg-gradient-to-r from-rose-950/30 via-slate-900/40 to-slate-900/40';
      case 'High Risk':
        return 'border-orange-900/60 bg-gradient-to-r from-orange-950/30 via-slate-900/40 to-slate-900/40';
      case 'Medium Risk':
        return 'border-yellow-900/60 bg-gradient-to-r from-yellow-950/20 via-slate-900/40 to-slate-900/40';
      case 'Low Risk':
        return 'border-emerald-900/60 bg-gradient-to-r from-emerald-950/20 via-slate-900/40 to-slate-900/40';
      default:
        return 'border-slate-800 bg-slate-900/40';
    }
  };

  const formattedDate = new Date(timestamp).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <div className={`p-5 rounded-xl border ${getBorderColor(riskBand)} backdrop-blur-sm transition-all`}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Category Header */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-slate-800/80 border border-slate-700/80">
            {getCategoryIcon(category)}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight">
                {categoryLabel}
              </h2>
            </div>
            {/* Zero-Pill Metadata Discipline */}
            <div className="flex items-center gap-2 text-xs text-slate-400 mt-0.5">
              <span className="capitalize">{detectedType} Analysis</span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3 text-slate-500" />
                <span>{formattedDate}</span>
              </span>
              <span aria-hidden="true" className="text-slate-600">·</span>
              <span>Air-Gapped Inspection</span>
            </div>
          </div>
        </div>
      </div>

      {/* Primary Summary Text */}
      <div className="mt-4 border-t border-slate-800/80 pt-3">
        <p className="text-sm leading-relaxed text-slate-300">
          {summary}
        </p>
      </div>
    </div>
  );
};
