import React from 'react';
import { ShieldAlert, Cpu, FileText, History, ShieldCheck, Lock } from 'lucide-react';

interface NavbarProps {
  currentTab: 'analyzer' | 'methodology' | 'about';
  setCurrentTab: (tab: 'analyzer' | 'methodology' | 'about') => void;
  onOpenHistory: () => void;
  historyCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  onOpenHistory,
  historyCount,
}) => {
  return (
    <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand */}
        <div 
          onClick={() => setCurrentTab('analyzer')} 
          className="flex cursor-pointer items-center gap-3 transition-opacity hover:opacity-90"
        >
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-500/30 text-cyan-400 shadow-sm shadow-cyan-950/50">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-bold tracking-tight text-white">
                Phish<span className="text-cyan-400">Guard</span>
              </span>
              <span className="hidden text-xs text-slate-500 sm:inline">v1.4</span>
            </div>
            <p className="text-[11px] text-slate-400 tracking-wide">Explainable Threat Analyzer</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 sm:gap-2">
          <button
            onClick={() => setCurrentTab('analyzer')}
            className={`flex items-center gap-2 px-3 py-2 text-xs sm:text-sm font-medium transition-colors ${
              currentTab === 'analyzer'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="h-4 w-4" />
            <span>Analyzer</span>
          </button>

          <button
            onClick={() => setCurrentTab('methodology')}
            className={`flex items-center gap-2 px-3 py-2 text-xs sm:text-sm font-medium transition-colors ${
              currentTab === 'methodology'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Cpu className="h-4 w-4" />
            <span>Methodology</span>
          </button>

          <button
            onClick={() => setCurrentTab('about')}
            className={`flex items-center gap-2 px-3 py-2 text-xs sm:text-sm font-medium transition-colors ${
              currentTab === 'about'
                ? 'text-cyan-400 border-b-2 border-cyan-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="h-4 w-4" />
            <span>About</span>
          </button>
        </nav>

        {/* Safe Network & History Controls */}
        <div className="flex items-center gap-3">
          <div className="hidden lg:flex items-center gap-1.5 text-xs text-slate-400 bg-slate-900/80 px-2.5 py-1 rounded border border-slate-800">
            <Lock className="h-3 w-3 text-emerald-400" />
            <span>Safe Air-Gapped Lexical Analysis</span>
          </div>

          <button
            onClick={onOpenHistory}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded transition-colors"
            title="Analysis History (Stored Locally)"
          >
            <History className="h-3.5 w-3.5 text-slate-400" />
            <span className="hidden sm:inline">History</span>
            {historyCount > 0 && (
              <span className="ml-1 px-1.5 py-0.2 text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 rounded">
                {historyCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
