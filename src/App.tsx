/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { HistoryDrawer } from './components/HistoryDrawer';
import { DashboardPage } from './pages/DashboardPage';
import { MethodologyPage } from './pages/MethodologyPage';
import { AboutPage } from './pages/AboutPage';
import { AnalysisHistoryItem, AnalysisResult } from './types/threat';
import { ShieldAlert, Lock, ExternalLink } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<'analyzer' | 'methodology' | 'about'>('analyzer');
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isHistoryEnabled, setIsHistoryEnabled] = useState(false);
  const [history, setHistory] = useState<AnalysisHistoryItem[]>([]);
  const [selectedResult, setSelectedResult] = useState<AnalysisResult | null>(null);

  // Initialize history settings from browser storage
  useEffect(() => {
    try {
      const enabledSetting = localStorage.getItem('phishguard_history_enabled');
      if (enabledSetting === 'true') {
        setIsHistoryEnabled(true);
        const savedHistory = localStorage.getItem('phishguard_history_items');
        if (savedHistory) {
          setHistory(JSON.parse(savedHistory));
        }
      }
    } catch {
      // LocalStorage access might be restricted in some iframe contexts
    }
  }, []);

  const handleToggleHistory = (enabled: boolean) => {
    setIsHistoryEnabled(enabled);
    try {
      localStorage.setItem('phishguard_history_enabled', enabled ? 'true' : 'false');
      if (!enabled) {
        localStorage.removeItem('phishguard_history_items');
        setHistory([]);
      }
    } catch {}
  };

  const handleSaveHistoryItem = (item: AnalysisHistoryItem) => {
    if (!isHistoryEnabled) return;
    const updated = [item, ...history.filter(h => h.id !== item.id)].slice(0, 50);
    setHistory(updated);
    try {
      localStorage.setItem('phishguard_history_items', JSON.stringify(updated));
    } catch {}
  };

  const handleClearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem('phishguard_history_items');
    } catch {}
  };

  const handleSelectHistoryItem = async (id: string) => {
    // Navigate to analyzer
    setCurrentTab('analyzer');
    // If full record was saved or can be re-queried
    const item = history.find(h => h.id === id);
    if (item) {
      // Trigger new analysis of the preview text
      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: item.preview, inputType: item.detectedType }),
        });
        if (res.ok) {
          const data = await res.json();
          setSelectedResult(data);
        }
      } catch (err) {
        console.error('Failed to reload history item:', err);
      }
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#050814] text-slate-100 cyber-grid cyber-radial">
      {/* Top Navigation */}
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        onOpenHistory={() => setIsHistoryOpen(true)}
        historyCount={history.length}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-6">
        {currentTab === 'analyzer' && (
          <DashboardPage
            onSaveHistoryItem={handleSaveHistoryItem}
            isHistoryEnabled={isHistoryEnabled}
            initialResult={selectedResult}
          />
        )}
        {currentTab === 'methodology' && <MethodologyPage />}
        {currentTab === 'about' && <AboutPage />}
      </main>

      {/* History Drawer Modal */}
      <HistoryDrawer
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        history={history}
        isHistoryEnabled={isHistoryEnabled}
        onToggleHistory={handleToggleHistory}
        onClearHistory={handleClearHistory}
        onSelectHistoryItem={handleSelectHistoryItem}
      />

      {/* Professional Cybersecurity Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/90 py-8 px-4 sm:px-6 lg:px-8 text-xs text-slate-400">
        <div className="mx-auto max-w-7xl flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-7 w-7 items-center justify-center rounded bg-cyan-950 border border-cyan-800 text-cyan-400">
              <ShieldAlert className="h-4 w-4" />
            </div>
            <div>
              <span className="font-bold text-white tracking-tight">PhishGuard</span>
              <span className="text-slate-500 ml-2">Explainable Threat Analyzer Tool</span>
            </div>
          </div>

          <div className="flex items-center gap-4 text-slate-400">
            <button
              onClick={() => setCurrentTab('methodology')}
              className="hover:text-cyan-400 transition-colors"
            >
              Methodology
            </button>
            <span aria-hidden="true" className="text-slate-700">·</span>
            <button
              onClick={() => setCurrentTab('about')}
              className="hover:text-cyan-400 transition-colors"
            >
              Specifications & Privacy
            </button>
          </div>

          <div className="text-slate-500 text-center sm:text-right">
            <span>Air-gapped lexical analysis · Zero external URL visits</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
