import React, { useState } from 'react';
import { Copy, Check, Download, RotateCcw, MessageSquareHeart } from 'lucide-react';
import { AnalysisResult } from '../types/threat';

interface ReportActionsProps {
  result: AnalysisResult;
  onReset: () => void;
  onOpenFeedback: () => void;
}

export const ReportActions: React.FC<ReportActionsProps> = ({
  result,
  onReset,
  onOpenFeedback,
}) => {
  const [copied, setCopied] = useState(false);

  const generateMarkdownReport = (r: AnalysisResult): string => {
    return `# PhishGuard Threat Analysis Report
Generated: ${new Date(r.timestamp).toUTCString()}
Scan ID: ${r.id}

## Overall Assessment
- **Risk Score:** ${r.riskScore}/100
- **Risk Band:** ${r.riskBand}
- **Primary Category:** ${r.categoryLabel}
- **Confidence:** ${r.confidence !== null ? `${Math.round(r.confidence * 100)}%` : 'N/A'}
- **Analysis Modality:** ${r.detectedType.toUpperCase()}
- **Computation Time:** ${r.computationTimeMs} ms

## Threat Summary
${r.summary}

## Diagnostic Indicators (${r.indicators.length})
${r.indicators.map((ind, i) => `${i + 1}. [${ind.severity.toUpperCase()}] **${ind.title}** (${ind.category})\n   - Description: ${ind.description}\n   - Why It Matters: ${ind.whyItMatters}${ind.evidenceSnippet ? `\n   - Evidence Snippet: \`${ind.evidenceSnippet}\`` : ''}`).join('\n\n')}

## Top Model Feature Contributions
${r.topFeatureContributions.map(f => `- "${f.feature}": Log-odds impact ${f.contribution > 0 ? `+${f.contribution}` : f.contribution} (${f.direction}) - ${f.description}`).join('\n')}

## Recommended Protective Protocols
${r.recommendations.map(rec => `- ${rec}`).join('\n')}

## Limitations & Disclaimer
${r.limitations.map(lim => `- ${lim}`).join('\n')}

---
Report produced by PhishGuard Threat Analyzer (Safe Air-Gapped Lexical Inspection)
`;
  };

  const handleCopy = () => {
    const report = generateMarkdownReport(result);
    navigator.clipboard.writeText(report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleDownload = (format: 'json' | 'txt') => {
    let content: string;
    let filename: string;
    let mimeType: string;

    if (format === 'json') {
      content = JSON.stringify(result, null, 2);
      filename = `phishguard_report_${result.id}.json`;
      mimeType = 'application/json';
    } else {
      content = generateMarkdownReport(result);
      filename = `phishguard_report_${result.id}.txt`;
      mimeType = 'text/plain';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-sm">
      <div className="flex items-center gap-2">
        <button
          onClick={onReset}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          <span>Analyze Another</span>
        </button>

        <button
          onClick={onOpenFeedback}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
        >
          <MessageSquareHeart className="h-3.5 w-3.5 text-cyan-400" />
          <span>Feedback</span>
        </button>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={handleCopy}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-200 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          <span>{copied ? 'Report Copied!' : 'Copy Report'}</span>
        </button>

        <div className="flex items-center rounded-lg border border-slate-700 bg-slate-800 p-0.5">
          <button
            onClick={() => handleDownload('txt')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors"
            title="Download formatted text report"
          >
            <Download className="h-3.5 w-3.5 text-cyan-400" />
            <span>TXT</span>
          </button>
          <span className="text-slate-600">|</span>
          <button
            onClick={() => handleDownload('json')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white transition-colors"
            title="Download raw JSON report"
          >
            <span>JSON</span>
          </button>
        </div>
      </div>
    </div>
  );
};
