import React, { useState } from 'react';
import { X, Send, CheckCircle2, ShieldAlert } from 'lucide-react';

interface FeedbackModalProps {
  analysisId: string;
  isOpen: boolean;
  onClose: () => void;
}

export const FeedbackModal: React.FC<FeedbackModalProps> = ({
  analysisId,
  isOpen,
  onClose,
}) => {
  const [assessment, setAssessment] = useState<'accurate' | 'false_positive' | 'false_negative' | 'uncertain'>('accurate');
  const [comments, setComments] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysisId,
          userAssessment: assessment,
          comments: comments.trim() || undefined,
        }),
      });

      if (res.ok) {
        setSubmitted(true);
        setTimeout(() => {
          setSubmitted(false);
          onClose();
        }, 1800);
      }
    } catch {
      // Fallback
      setSubmitted(true);
      setTimeout(() => {
        setSubmitted(false);
        onClose();
      }, 1500);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2 text-white font-bold text-sm">
            <ShieldAlert className="h-4 w-4 text-cyan-400" />
            <span>Provide Threat Assessment Feedback</span>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {submitted ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <CheckCircle2 className="h-10 w-10 text-emerald-400 mb-2" />
            <h4 className="text-sm font-semibold text-white">Thank You for Your Feedback!</h4>
            <p className="text-xs text-slate-400 mt-1">
              Your assessment helps calibrate our transparent heuristic weights. No message content was retained.
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="mt-4 space-y-4">
            <div>
              <label className="text-xs font-medium text-slate-300 block mb-2">
                How accurate was this threat triage decision?
              </label>
              <div className="space-y-2">
                {[
                  { value: 'accurate', label: 'Accurate — Result matches threat expectation' },
                  { value: 'false_positive', label: 'False Positive — Benign text was flagged as threat' },
                  { value: 'false_negative', label: 'False Negative — Malicious content scored as safe' },
                  { value: 'uncertain', label: 'Uncertain / Context dependent' },
                ].map(opt => (
                  <label
                    key={opt.value}
                    className={`flex items-center gap-2.5 p-2 rounded-lg border text-xs cursor-pointer transition-colors ${
                      assessment === opt.value
                        ? 'bg-slate-800 border-cyan-500/50 text-white'
                        : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <input
                      type="radio"
                      name="assessment"
                      value={opt.value}
                      checked={assessment === opt.value}
                      onChange={() => setAssessment(opt.value as any)}
                      className="accent-cyan-400"
                    />
                    <span>{opt.label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 block mb-1">
                Optional comments or observed indicators (max 500 chars):
              </label>
              <textarea
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                maxLength={500}
                rows={3}
                placeholder="E.g. The message was an authentic internal meeting reminder from our IT department..."
                className="w-full rounded-lg border border-slate-800 bg-slate-950 p-2.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex items-center gap-1.5 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white hover:bg-cyan-500 transition-colors disabled:opacity-50"
              >
                <Send className="h-3.5 w-3.5" />
                <span>{loading ? 'Submitting...' : 'Submit Assessment'}</span>
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
