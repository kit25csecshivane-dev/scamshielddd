import React from 'react';
import { X, Trash2, Download, History, Shield, ExternalLink } from 'lucide-react';
import { AnalysisHistoryItem, RiskBand } from '../types/threat';

interface HistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  history: AnalysisHistoryItem[];
  isHistoryEnabled: boolean;
  onToggleHistory: (enabled: boolean) => void;
  onClearHistory: () => void;
  onSelectHistoryItem: (id: string) => void;
}

export const HistoryDrawer: React.FC<HistoryDrawerProps> = ({
  isOpen,
  onClose,
  history,
  isHistoryEnabled,
  onToggleHistory,
  onClearHistory,
  onSelectHistoryItem,
}) => {
  if (!isOpen) return null;

  const getRiskColor = (band: RiskBand) => {
    switch (band) {
      case 'Critical Risk':
        return 'text-rose-400 border-rose-900/50 bg-rose-950/20';
      case 'High Risk':
        return 'text-orange-400 border-orange-900/50 bg-orange-950/20';
      case 'Medium Risk':
        return 'text-yellow-400 border-yellow-900/50 bg-yellow-950/20';
      case 'Low Risk':
        return 'text-emerald-400 border-emerald-900/50 bg-emerald-950/20';
      default:
        return 'text-slate-400 border-slate-800 bg-slate-900/40';
    }
  };

  const exportHistory = () => {
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard_history_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
      <div className="flex h-full w-full max-w-md flex-col border-l border-slate-800 bg-slate-950 p-6 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2">
            <History className="h-5 w-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">Local Analysis History</h3>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-slate-400 hover:text-white transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Privacy Toggle (Disabled by default per report specifications) */}
        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900/60 p-3.5 text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyan-400 shrink-0" />
              <span className="font-medium text-slate-200">Save Local History</span>
            </div>
            <label className="relative inline-flex cursor-pointer items-center">
              <input
                type="checkbox"
                checked={isHistoryEnabled}
                onChange={(e) => onToggleHistory(e.target.checked)}
                className="peer sr-only"
              />
              <div className="peer h-5 w-9 rounded-full bg-slate-800 after:absolute after:top-[2px] after:left-[2px] after:h-4 after:w-4 after:rounded-full after:bg-slate-400 after:transition-all after:content-[''] peer-checked:bg-cyan-600 peer-checked:after:translate-x-full peer-checked:after:bg-white"></div>
            </label>
          </div>
          <p className="mt-2 text-[11px] text-slate-400 leading-relaxed">
            By default, PhishGuard does not store your analyzed messages anywhere. Enabling this keeps a local record solely inside your browser's private storage.
          </p>
        </div>

        {/* History List */}
        <div className="mt-4 flex-1 overflow-y-auto space-y-2.5 pr-1">
          {!isHistoryEnabled ? (
            <div className="flex flex-col items-center justify-center h-48 text-center text-xs text-slate-500">
              <History className="h-8 w-8 mb-2 text-slate-600" />
              <span>History is currently disabled for maximum privacy.</span>
              <span className="mt-1 text-[11px] text-slate-600">Turn on the toggle above to save future scans locally.</span>
            </div>
          ) : history.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-center text-xs text-slate-500">
              <span>No scans recorded yet.</span>
              <span className="mt-1 text-[11px]">Submissions will appear here once analyzed.</span>
            </div>
          ) : (
            history.map((item) => (
              <div
                key={item.id}
                onClick={() => {
                  onSelectHistoryItem(item.id);
                  onClose();
                }}
                className="cursor-pointer rounded-lg border border-slate-800/80 bg-slate-900/40 p-3 text-xs transition-all hover:border-slate-700 hover:bg-slate-900"
              >
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getRiskColor(item.riskBand)}`}>
                    {item.riskBand} ({item.riskScore})
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>

                <div className="mt-2 font-mono text-[11px] text-slate-300 truncate">
                  {item.preview}
                </div>

                <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-500">
                  <span className="capitalize">{item.detectedType}</span>
                  <span className="flex items-center gap-1 text-cyan-400 hover:underline">
                    View Report <ExternalLink className="h-2.5 w-2.5" />
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer actions */}
        {isHistoryEnabled && history.length > 0 && (
          <div className="mt-4 flex items-center justify-between border-t border-slate-800 pt-3">
            <button
              onClick={onClearHistory}
              className="flex items-center gap-1.5 text-xs text-rose-400 hover:text-rose-300 transition-colors"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>Clear History</span>
            </button>

            <button
              onClick={exportHistory}
              className="flex items-center gap-1.5 text-xs text-slate-300 hover:text-white transition-colors"
            >
              <Download className="h-3.5 w-3.5 text-cyan-400" />
              <span>Export JSON</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
