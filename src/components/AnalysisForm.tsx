import React from 'react';
import { 
  Search, 
  Trash2, 
  Globe, 
  Mail, 
  MessageSquare, 
  Share2, 
  FileText, 
  Sparkles, 
  ShieldCheck, 
  Lock 
} from 'lucide-react';

export type InputMode = 'auto' | 'url' | 'email' | 'sms' | 'social' | 'other';

interface AnalysisFormProps {
  content: string;
  setContent: (val: string) => void;
  inputMode: InputMode;
  setInputMode: (mode: InputMode) => void;
  onAnalyze: () => void;
  onClear: () => void;
  loading: boolean;
  error?: string | null;
}

export const AnalysisForm: React.FC<AnalysisFormProps> = ({
  content,
  setContent,
  inputMode,
  setInputMode,
  onAnalyze,
  onClear,
  loading,
  error,
}) => {
  const charLimit = 25000;
  const charCount = content.length;

  const examples = [
    {
      label: 'Suspicious OTP Request',
      category: 'SMS / Smishing',
      mode: 'sms' as InputMode,
      text: 'URGENT: Bank of America Fraud Alert. Unauthorized sign-in detected on your account. Send your one-time password (OTP) code immediately within 24 hours to prevent permanent account suspension.',
    },
    {
      label: 'Deceptive URL with IP & Subdomains',
      category: 'URL / Phishing',
      mode: 'url' as InputMode,
      text: 'http://192.168.1.100/paypal.com.verify-account-security.xyz/login.php?token=92837482&redirect=https://paypal.com',
    },
    {
      label: 'Fake Job Offer & Starter Kit',
      category: 'Recruitment Scam',
      mode: 'email' as InputMode,
      text: 'Congratulations! You have been selected for the Data Entry Specialist role paying $450/day. No interview needed! Instant hiring. Please purchase your home office equipment starter kit for $199 via Western Union to begin onboarding.',
    },
    {
      label: 'Guaranteed Crypto Returns',
      category: 'Investment Fraud',
      mode: 'other' as InputMode,
      text: 'Guaranteed 300% returns in 24 hours! 100% risk-free automated crypto trading bot. Send 0.2 BTC to our verified pool and double your money today. Contact @cryptoprofits on Telegram.',
    },
    {
      label: 'Legitimate Project Invitation',
      category: 'Benign Communication',
      mode: 'email' as InputMode,
      text: 'Hi Team, please find attached the meeting agenda and quarterly project review slide deck for tomorrow’s coordination call at 10:00 AM. Let me know if you would like to include additional discussion items. Sincerely, Alex.',
    },
  ];

  const handleSelectExample = (ex: typeof examples[0]) => {
    setContent(ex.text);
    setInputMode(ex.mode);
  };

  const getPlaceholder = (mode: InputMode) => {
    switch (mode) {
      case 'url':
        return 'Paste a suspicious URL to inspect (e.g., http://login-secure-update.xyz/verify)...';
      case 'email':
        return 'Paste email subject line, headers, and message body here...';
      case 'sms':
        return 'Paste suspicious SMS message text (smishing)...';
      case 'social':
        return 'Paste direct message, social media offer, or unverified link message...';
      case 'other':
        return 'Paste job offer, investment pitch, lottery message, or advertisement...';
      case 'auto':
      default:
        return 'Paste any suspicious URL, email, SMS, fake job offer, crypto investment pitch, or message text here for explainable threat triage...';
    }
  };

  return (
    <div className="rounded-2xl border border-slate-800/90 bg-slate-900/60 p-5 sm:p-7 backdrop-blur-md shadow-2xl">
      {/* Input Modality Selectors (Functional Tab Controls) */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-800/80 pb-4">
        <span className="text-xs font-semibold text-slate-400 mr-2">Input Mode:</span>

        {[
          { id: 'auto', label: 'Auto Detect', icon: Sparkles },
          { id: 'url', label: 'Suspicious URL', icon: Globe },
          { id: 'email', label: 'Email Content', icon: Mail },
          { id: 'sms', label: 'SMS / Text', icon: MessageSquare },
          { id: 'social', label: 'Social Media', icon: Share2 },
          { id: 'other', label: 'Other Scam Text', icon: FileText },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = inputMode === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setInputMode(tab.id as InputMode)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                isActive
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                  : 'bg-slate-950/40 text-slate-400 border border-slate-800 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Main Textarea Area */}
      <div className="mt-4 relative">
        <textarea
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder={getPlaceholder(inputMode)}
          rows={6}
          className="w-full rounded-xl border border-slate-800 bg-slate-950/80 p-4 font-mono text-xs sm:text-sm text-slate-100 placeholder:text-slate-600 focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/40 focus:outline-none transition-all resize-y leading-relaxed"
        />

        {/* Character Counter & Clear */}
        <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span>
              {charCount.toLocaleString()} / {charLimit.toLocaleString()} chars
            </span>
            {charCount > 20000 && (
              <span className="text-amber-400 text-[11px]">(Approaching maximum limit)</span>
            )}
          </div>

          {content && (
            <button
              type="button"
              onClick={onClear}
              className="flex items-center gap-1 text-slate-400 hover:text-rose-400 text-xs transition-colors"
            >
              <Trash2 className="h-3 w-3" />
              <span>Clear Input</span>
            </button>
          )}
        </div>
      </div>

      {/* Error Message if present */}
      {error && (
        <div className="mt-3 rounded-lg border border-rose-900/50 bg-rose-950/20 p-3 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Action CTA & Privacy Assurance */}
      <div className="mt-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-4 border-t border-slate-800/80">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Lock className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>
            Safe Inspection: Content is never stored without permission or probed across external networks.
          </span>
        </div>

        <button
          type="button"
          onClick={onAnalyze}
          disabled={loading || !content.trim()}
          className="flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-500 px-6 py-2.5 text-sm font-semibold text-white shadow-lg shadow-cyan-950/60 hover:from-cyan-500 hover:to-cyan-400 active:scale-[0.99] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
              <span>Analyzing Threat Signals...</span>
            </>
          ) : (
            <>
              <Search className="h-4 w-4" />
              <span>Analyze Threat</span>
            </>
          )}
        </button>
      </div>

      {/* Quick Test Demonstration Examples */}
      <div className="mt-6 border-t border-slate-800/80 pt-4">
        <div className="flex items-center gap-2 mb-2.5">
          <ShieldCheck className="h-3.5 w-3.5 text-cyan-400" />
          <span className="text-xs font-semibold text-slate-300">
            Quick Demonstration Samples (Click to load, then click Analyze):
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          {examples.map((ex, i) => (
            <button
              key={i}
              type="button"
              onClick={() => handleSelectExample(ex)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-800/90 bg-slate-950/50 hover:bg-slate-800 text-xs text-slate-300 hover:text-white transition-colors"
            >
              <span className="font-medium text-cyan-400">Sample {i + 1}:</span>
              <span>{ex.label}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
