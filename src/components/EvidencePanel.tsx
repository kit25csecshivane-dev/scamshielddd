import React, { useState } from 'react';
import { 
  AlertCircle, 
  CheckCircle2, 
  HelpCircle, 
  Info, 
  Layers, 
  Network, 
  Globe, 
  Compass, 
  ChevronDown, 
  ChevronUp 
} from 'lucide-react';
import { DetectedIndicator, IndicatorSeverity, UrlMetrics } from '../types/threat';

interface EvidencePanelProps {
  indicators: DetectedIndicator[];
  urlMetrics?: UrlMetrics;
  differenceExplanation: string;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({
  indicators,
  urlMetrics,
  differenceExplanation,
}) => {
  const [filter, setFilter] = useState<'all' | 'critical_high' | 'url_metrics'>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const getSeverityBadge = (sev: IndicatorSeverity) => {
    switch (sev) {
      case 'critical':
        return <span className="text-xs font-semibold text-rose-400">Critical Threat</span>;
      case 'high':
        return <span className="text-xs font-semibold text-orange-400">High Risk</span>;
      case 'medium':
        return <span className="text-xs font-medium text-yellow-400">Moderate Signal</span>;
      case 'low':
        return <span className="text-xs font-medium text-cyan-400">Low Signal</span>;
      case 'neutral':
      default:
        return <span className="text-xs text-slate-400">Contextual / Informational</span>;
    }
  };

  const filteredIndicators = indicators.filter(ind => {
    if (filter === 'critical_high') {
      return ind.severity === 'critical' || ind.severity === 'high';
    }
    return true;
  });

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 backdrop-blur-sm">
      {/* Header and Filter Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div>
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            <span>Diagnostic Evidence & Threat Signals</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Empirical structural and lexical triggers observed during analysis ({indicators.length} total)
          </p>
        </div>

        {/* Filter Controls (Allowed interactive tabs per Anti-Slop constitution) */}
        <div className="flex items-center gap-1 p-1 bg-slate-950/80 rounded-lg border border-slate-800 self-start sm:self-auto">
          <button
            onClick={() => setFilter('all')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors ${
              filter === 'all'
                ? 'bg-slate-800 text-cyan-300 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Signals ({indicators.length})
          </button>
          <button
            onClick={() => setFilter('critical_high')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors ${
              filter === 'critical_high'
                ? 'bg-slate-800 text-rose-300 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            High & Critical ({indicators.filter(i => i.severity === 'critical' || i.severity === 'high').length})
          </button>
          {urlMetrics && (
            <button
              onClick={() => setFilter('url_metrics')}
              className={`px-2.5 py-1 text-xs font-medium rounded transition-colors ${
                filter === 'url_metrics'
                  ? 'bg-slate-800 text-cyan-300 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              URL Breakdown
            </button>
          )}
        </div>
      </div>

      {/* URL Structural Breakdown view */}
      {filter === 'url_metrics' && urlMetrics && (
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Globe className="h-3.5 w-3.5 text-cyan-400" />
              <span>Resolved Hostname</span>
            </div>
            <div className="mt-1 font-mono text-xs font-medium text-slate-200 break-all">
              {urlMetrics.hostname}
            </div>
            <div className="mt-2 text-[11px] text-slate-400">
              {urlMetrics.isIpAddress ? 'Direct IP format (High Risk)' : `Domain: ${urlMetrics.domain}`}
            </div>
          </div>

          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Network className="h-3.5 w-3.5 text-cyan-400" />
              <span>Subdomains & TLD</span>
            </div>
            <div className="mt-1 font-mono text-xs font-medium text-slate-200">
              .{urlMetrics.tld || 'none'}
            </div>
            <div className="mt-2 text-[11px] text-slate-400">
              {urlMetrics.dotsInHostname} dots · {urlMetrics.subdomains.length} subdomain tiers
            </div>
          </div>

          <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60">
            <div className="flex items-center gap-1.5 text-xs text-slate-400">
              <Compass className="h-3.5 w-3.5 text-cyan-400" />
              <span>Length & Parameters</span>
            </div>
            <div className="mt-1 font-mono text-xs font-medium text-slate-200">
              {urlMetrics.totalLength} chars · {urlMetrics.pathDepth} path levels
            </div>
            <div className="mt-2 text-[11px] text-slate-400">
              {urlMetrics.queryParamCount} query parameter(s) detected
            </div>
          </div>
        </div>
      )}

      {/* Indicator list */}
      {filter !== 'url_metrics' && (
        <div className="mt-4 space-y-3">
          {filteredIndicators.length === 0 ? (
            <div className="flex items-center gap-2 p-4 text-xs text-slate-400 bg-slate-950/50 rounded-lg border border-slate-800">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <span>No severe indicators found under this filter criteria.</span>
            </div>
          ) : (
            filteredIndicators.map((ind) => {
              const isExpanded = expandedId === ind.id;
              return (
                <div
                  key={ind.id}
                  className="rounded-lg border border-slate-800/90 bg-slate-950/50 p-4 transition-all hover:border-slate-700"
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        {getSeverityBadge(ind.severity)}
                        <span aria-hidden="true" className="text-slate-600">·</span>
                        <span className="text-xs text-slate-400">{ind.category}</span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-200">
                        {ind.title}
                      </h4>
                    </div>

                    <button
                      onClick={() => setExpandedId(isExpanded ? null : ind.id)}
                      className="self-end sm:self-auto flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono transition-colors"
                    >
                      <span>{isExpanded ? 'Hide Details' : 'Why It Matters'}</span>
                      {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                    </button>
                  </div>

                  <p className="mt-2 text-xs text-slate-300 leading-relaxed">
                    {ind.description}
                  </p>

                  {/* Evidence snippet */}
                  {ind.evidenceSnippet && (
                    <div className="mt-2 flex items-center gap-2 text-xs">
                      <span className="text-slate-500 font-mono">Evidence token:</span>
                      <code className="rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] text-cyan-300 border border-slate-800">
                        {ind.evidenceSnippet}
                      </code>
                    </div>
                  )}

                  {/* Expandable "Why It Matters" panel */}
                  {isExpanded && (
                    <div className="mt-3 rounded border border-cyan-950 bg-cyan-950/20 p-3 text-xs text-cyan-200/90 leading-relaxed">
                      <div className="font-semibold text-cyan-400 mb-1 flex items-center gap-1.5">
                        <Info className="h-3.5 w-3.5" />
                        <span>Cybersecurity Rationale:</span>
                      </div>
                      <p>{ind.whyItMatters}</p>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Methodological Difference Explanation (Requirement 8) */}
      <div className="mt-5 rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 text-xs text-slate-400 leading-relaxed">
        <div className="flex items-start gap-2">
          <AlertCircle className="h-4 w-4 text-slate-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-slate-300">Evidence vs Inferred Risk: </span>
            <span>{differenceExplanation}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
