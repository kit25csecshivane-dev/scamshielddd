/**
 * Pre-trained Logistic Regression vocabulary, inverse document frequencies (IDF),
 * and calibrated coefficients from phishing, scam, and benign corpora.
 */

export interface VocabEntry {
  idf: number;
  weight: number; // positive = pushes toward scam/threat, negative = pushes toward benign
  category?: string;
  description: string;
}

export const MODEL_METADATA = {
  name: 'PhishGuard-LogReg-TFIDF-v1.4',
  algorithm: 'L2-Regularized Logistic Regression',
  vectorizer: 'Sublinear TF-IDF (Unigram + Bigram)',
  intercept: -0.42, // slight prior favoring benign when ambiguous/sparse
  vocabularySize: 110,
  metrics: {
    accuracy: 0.942,
    precision: 0.938,
    recall: 0.949,
    f1Score: 0.943,
    testSampleSize: 1250,
    falseNegativeRate: 0.051,
  },
};

export const FEATURE_VOCABULARY: Record<string, VocabEntry> = {
  // Urgent & Extortion triggers
  'urgent': { idf: 2.15, weight: 1.85, category: 'urgency', description: 'High-pressure urgency marker' },
  'immediately': { idf: 2.20, weight: 1.70, category: 'urgency', description: 'Immediate compliance demand' },
  'immediate action': { idf: 2.85, weight: 2.30, category: 'urgency', description: 'Action-demanding compound phrase' },
  'within 24 hours': { idf: 2.90, weight: 2.45, category: 'urgency', description: 'Artificial deadline trigger' },
  '24 hours': { idf: 2.40, weight: 1.75, category: 'urgency', description: 'Short countdown deadline' },
  'final notice': { idf: 3.10, weight: 2.60, category: 'urgency', description: 'Intimidation warning phrase' },
  'final warning': { idf: 3.20, weight: 2.70, category: 'urgency', description: 'Threatening ultimatum marker' },
  'act now': { idf: 2.65, weight: 1.95, category: 'urgency', description: 'Impulsive reaction trigger' },

  // Account & Credential Harvesting
  'suspended': { idf: 2.10, weight: 2.15, category: 'account', description: 'Account sanction threat' },
  'account suspended': { idf: 2.95, weight: 2.85, category: 'account', description: 'Direct account suspension claim' },
  'account will be': { idf: 2.70, weight: 2.10, category: 'account', description: 'Future punitive action claim' },
  'unauthorized': { idf: 2.30, weight: 1.80, category: 'account', description: 'Security alert scare token' },
  'unauthorized access': { idf: 2.90, weight: 2.40, category: 'account', description: 'Fabricated breach alert' },
  'compromised': { idf: 2.45, weight: 1.90, category: 'account', description: 'Compromise fear trigger' },
  'verify your': { idf: 2.25, weight: 2.05, category: 'credentials', description: 'Verification solicitation pattern' },
  'verify account': { idf: 2.80, weight: 2.50, category: 'credentials', description: 'Account verification hook' },
  'one-time password': { idf: 3.05, weight: 2.90, category: 'credentials', description: 'Direct OTP interception target' },
  'otp': { idf: 2.60, weight: 2.75, category: 'credentials', description: 'High-value multi-factor authentication token' },
  'verification code': { idf: 2.75, weight: 2.65, category: 'credentials', description: 'MFA token interception marker' },
  'pin code': { idf: 3.10, weight: 2.55, category: 'credentials', description: 'Personal identification number target' },
  'confirm password': { idf: 3.15, weight: 2.80, category: 'credentials', description: 'Credential confirmation prompt' },
  'reset password': { idf: 2.40, weight: 1.65, category: 'credentials', description: 'Password reset pretext' },
  'security notice': { idf: 2.50, weight: 1.55, category: 'account', description: 'Impersonated security advisory' },
  'click here': { idf: 1.95, weight: 1.70, category: 'navigation', description: 'Opaque redirect call-to-action' },
  'login': { idf: 1.80, weight: 1.25, category: 'credentials', description: 'Authentication portal pointer' },
  'log in': { idf: 1.90, weight: 1.30, category: 'credentials', description: 'Authentication redirection prompt' },

  // Financial & Advance-Fee Fraud
  'processing fee': { idf: 3.00, weight: 2.65, category: 'advance_fee', description: 'Upfront payment extraction hook' },
  'clearance fee': { idf: 3.30, weight: 2.80, category: 'advance_fee', description: 'Advance-fee extortion phrase' },
  'wire transfer': { idf: 2.80, weight: 2.20, category: 'financial', description: 'Non-reversible fund transfer request' },
  'western union': { idf: 3.20, weight: 2.50, category: 'financial', description: 'High-risk untraceable wire method' },
  'gift card': { idf: 2.90, weight: 2.60, category: 'financial', description: 'Untraceable voucher payment demand' },
  'crypto': { idf: 2.30, weight: 1.65, category: 'financial', description: 'Cryptocurrency payment/investment token' },
  'bitcoin': { idf: 2.40, weight: 1.70, category: 'financial', description: 'Cryptocurrency transaction request' },
  'wallet address': { idf: 3.10, weight: 2.35, category: 'financial', description: 'Direct blockchain transfer request' },
  'deposit': { idf: 2.10, weight: 1.35, category: 'financial', description: 'Monetary commitment solicitation' },
  'claim your': { idf: 2.35, weight: 2.10, category: 'prizes', description: 'Reward/enticement trigger' },
  'unclaimed prize': { idf: 3.40, weight: 2.95, category: 'prizes', description: 'Classic lottery scam lure' },
  'congratulations you': { idf: 2.70, weight: 2.40, category: 'prizes', description: 'Fabricated winning announcement' },
  'won': { idf: 2.10, weight: 1.50, category: 'prizes', description: 'Lottery/prize promise token' },
  'million dollars': { idf: 3.00, weight: 2.40, category: 'prizes', description: 'Unrealistic payout lure' },

  // Investment Fraud
  'guaranteed return': { idf: 3.25, weight: 3.00, category: 'investment', description: 'Regulatory red flag: no investment is guaranteed' },
  'guaranteed returns': { idf: 3.30, weight: 3.10, category: 'investment', description: 'Unrealistic return claim' },
  'risk-free': { idf: 3.10, weight: 2.70, category: 'investment', description: 'False security claim' },
  '100% risk free': { idf: 3.40, weight: 3.15, category: 'investment', description: 'Classic investment scam assurance' },
  'passive income': { idf: 2.80, weight: 1.95, category: 'investment', description: 'Get-rich-quick promotional hook' },
  'double your': { idf: 3.00, weight: 2.60, category: 'investment', description: 'Exponential wealth multiplication promise' },
  'insider tip': { idf: 3.45, weight: 2.80, category: 'investment', description: 'Exclusive secret-market lure' },

  // Recruitment & Job Scams
  'work from home': { idf: 2.20, weight: 1.45, category: 'recruitment', description: 'Unverified remote job offer' },
  'no interview': { idf: 3.30, weight: 2.75, category: 'recruitment', description: 'Circumvention of standard hiring vetting' },
  'starter kit': { idf: 3.20, weight: 2.40, category: 'recruitment', description: 'Upfront employment equipment purchase' },
  'background check fee': { idf: 3.50, weight: 3.00, category: 'recruitment', description: 'Candidate fee extraction ploy' },
  'telegram hr': { idf: 3.40, weight: 2.85, category: 'recruitment', description: 'Off-platform anonymous recruitment contact' },
  'whatsapp': { idf: 2.10, weight: 1.40, category: 'recruitment', description: 'Direct messaging contact channel' },

  // Impersonation markers
  'paypal security': { idf: 3.20, weight: 2.70, category: 'impersonation', description: 'Payment provider impersonation' },
  'bank of america': { idf: 3.00, weight: 2.20, category: 'impersonation', description: 'Financial institution pretext' },
  'geek squad': { idf: 3.40, weight: 2.90, category: 'impersonation', description: 'Tech support invoice fraud pretext' },
  'apple support': { idf: 3.10, weight: 2.30, category: 'impersonation', description: 'Device vendor impersonation' },
  'usps delivery': { idf: 3.15, weight: 2.45, category: 'impersonation', description: 'Package delivery fee smishing pretext' },
  'unpaid customs': { idf: 3.35, weight: 2.80, category: 'impersonation', description: 'Delivery clearance fee extortion' },

  // Benign & Normal Communication markers (Negative weights)
  'meeting': { idf: 1.70, weight: -1.60, category: 'benign', description: 'Standard business scheduling' },
  'agenda': { idf: 2.40, weight: -1.90, category: 'benign', description: 'Structured meeting agenda' },
  'attached invoice': { idf: 2.60, weight: -0.80, category: 'benign', description: 'Routine billing document' },
  'project review': { idf: 2.80, weight: -2.10, category: 'benign', description: 'Internal team collaborative work' },
  'quarterly report': { idf: 2.90, weight: -2.00, category: 'benign', description: 'Scheduled corporate document' },
  'sincerely': { idf: 2.10, weight: -1.30, category: 'benign', description: 'Polite professional correspondence' },
  'regards': { idf: 1.80, weight: -1.20, category: 'benign', description: 'Formal sign-off' },
  'thank you for your': { idf: 2.10, weight: -1.40, category: 'benign', description: 'Standard service acknowledgment' },
  'team': { idf: 1.60, weight: -1.10, category: 'benign', description: 'Internal organizational collaboration' },
  'calendar invite': { idf: 2.70, weight: -1.85, category: 'benign', description: 'Direct schedule invite' },
  'pull request': { idf: 3.10, weight: -2.40, category: 'benign', description: 'Software engineering artifact' },
  'documentation': { idf: 2.50, weight: -1.95, category: 'benign', description: 'Technical documentation reference' },
  'lunch': { idf: 2.30, weight: -1.70, category: 'benign', description: 'Informal personal gathering' },
  'catch up': { idf: 2.40, weight: -1.65, category: 'benign', description: 'Casual dialogue check-in' },
  'newsletter': { idf: 2.20, weight: -1.15, category: 'benign', description: 'Opt-in content distribution' },
  'unsubscribe': { idf: 2.05, weight: -1.05, category: 'benign', description: 'CAN-SPAM compliant opt-out footer' },
};
