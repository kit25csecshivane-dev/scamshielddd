import React from 'react';
import { HighlightSpan, IndicatorSeverity } from '../types/threat';

interface HighlightedTextProps {
  text: string;
  spans: HighlightSpan[];
  isUrl: boolean;
}

export const HighlightedText: React.FC<HighlightedTextProps> = ({
  text,
  spans,
  isUrl,
}) => {
  if (!text) return null;

  // If no highlights or short text, render clean text
  if (spans.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4 font-mono text-xs sm:text-sm text-slate-300 leading-relaxed whitespace-pre-wrap break-all select-all">
        {text}
      </div>
    );
  }

  // Sort spans by start offset
  const sorted = [...spans].sort((a, b) => a.start - b.end);

  // Merge / build segments
  const segments: React.ReactNode[] = [];
  let currentIndex = 0;

  const getSeverityStyle = (severity: IndicatorSeverity) => {
    switch (severity) {
      case 'critical':
        return 'bg-rose-500/25 border-b-2 border-rose-500 text-rose-200 font-semibold';
      case 'high':
        return 'bg-orange-500/25 border-b-2 border-orange-500 text-orange-200 font-semibold';
      case 'medium':
        return 'bg-yellow-500/25 border-b-2 border-yellow-500 text-yellow-200 font-medium';
      default:
        return 'bg-cyan-500/20 border-b border-cyan-500 text-cyan-200';
    }
  };

  sorted.forEach((span, i) => {
    // Normal text before this span
    if (span.start > currentIndex) {
      segments.push(
        <span key={`txt_${currentIndex}`}>
          {text.substring(currentIndex, span.start)}
        </span>
      );
    }

    // Highlighted span
    const matchText = text.substring(span.start, span.end);
    segments.push(
      <mark
        key={`mark_${span.start}_${i}`}
        className={`relative inline px-1 py-0.5 rounded-sm ${getSeverityStyle(span.severity)} transition-all`}
        title={`Identified: ${span.label}`}
      >
        {matchText}
        <span className="sr-only"> ({span.label})</span>
      </mark>
    );

    currentIndex = Math.max(currentIndex, span.end);
  });

  // Trailing text
  if (currentIndex < text.length) {
    segments.push(
      <span key={`txt_end`}>
        {text.substring(currentIndex)}
      </span>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>Inspected Content {isUrl ? '(Lexical Segmentation)' : '(Trigger Tokens Highlighted)'}:</span>
        <span className="text-[11px] text-slate-500">{spans.length} trigger phrase(s) marked</span>
      </div>
      <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-4 font-mono text-xs sm:text-sm text-slate-200 leading-relaxed whitespace-pre-wrap break-all select-all">
        {segments}
      </div>
    </div>
  );
};
