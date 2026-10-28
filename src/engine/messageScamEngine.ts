import { DetectedIndicator, HighlightSpan, ThreatCategory } from '../types/threat';

export interface MessageRuleGroup {
  id: string;
  category: string;
  threatCategory: ThreatCategory;
  title: string;
  whyItMatters: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  patterns: Array<{
    regex: RegExp;
    label: string;
    description: string;
    weight: number;
  }>;
}

const MESSAGE_RULE_GROUPS: MessageRuleGroup[] = [
  // 1. Direct Credential & OTP Interception
  {
    id: 'grp_credentials',
    category: 'Credential Harvesting',
    threatCategory: 'credential_harvesting',
    title: 'Credential or Multi-Factor Authentication (OTP) Solicitation',
    whyItMatters: 'Authentic institutions will never ask for your password, PIN, or one-time verification code via email, SMS, or phone. This is the primary mechanism for account takeover.',
    severity: 'critical',
    patterns: [
      {
        regex: /\b(one[- ]time password|otp|verification code|security code|passcode|pin code|auth code)\b/i,
        label: 'MFA/OTP Token Request',
        description: 'Explicit request for a temporary authentication passcode or OTP token.',
        weight: 35,
      },
      {
        regex: /\b(share (your )?(password|credentials|pin|passcode)|confirm (your )?password|enter (your )?password)\b/i,
        label: 'Direct Password Elicitation',
        description: 'Direct demand to provide or verify account passwords.',
        weight: 40,
      },
    ],
  },

  // 2. Coercive Urgency & Account Sanction Threats
  {
    id: 'grp_urgency_threats',
    category: 'Psychological Coercion',
    threatCategory: 'urgency_extortion',
    title: 'Manufactured Urgency and Account Sanction Threats',
    whyItMatters: 'Social engineers fabricate immediate deadlines and threaten account suspension to bypass rational scrutiny and trigger panic-driven compliance.',
    severity: 'high',
    patterns: [
      {
        regex: /\b(within (24|12|48|2) hours|immediate action (is )?required|act immediately|final notice|final warning|last warning|account will be (permanently )?(suspended|closed|terminated|locked|disabled))\b/i,
        label: 'Urgency & Account Termination Threat',
        description: 'Imminent threat of account restriction combined with severe time pressure.',
        weight: 30,
      },
      {
        regex: /\b(unauthorized (access|transaction|login)|suspicious activity detected|unusual sign[- ]in|security compromise)\b/i,
        label: 'Fabricated Security Alert',
        description: 'Pretextual security incident claim used to induce anxiety.',
        weight: 20,
      },
    ],
  },

  // 3. Upfront Fees & Advance-Fee Fraud
  {
    id: 'grp_advance_fee',
    category: 'Advance-Fee Fraud',
    threatCategory: 'advance_fee_scam',
    title: 'Advance-Fee and Untraceable Payment Demand',
    whyItMatters: 'Demanding payment via untraceable means (crypto, wire transfers, prepaid gift cards) or claiming an upfront fee is required to release larger funds is standard 419/advance-fee fraud.',
    severity: 'high',
    patterns: [
      {
        regex: /\b(processing fee|clearance fee|handling fee|registration fee|customs fee|administrative charge)\b/i,
        label: 'Upfront Clearance Fee',
        description: 'Demand for an upfront monetary charge prior to receiving a supposed benefit.',
        weight: 30,
      },
      {
        regex: /\b(apple gift card|steam card|google play card|vanilla visa|western union|moneygram|wire transfer to)\b/i,
        label: 'Irreversible / Untraceable Payment Channel',
        description: 'Demand for payment using untraceable vouchers or non-reversible money transfers.',
        weight: 35,
      },
    ],
  },

  // 4. Guaranteed Investment & Cryptocurrency Fraud
  {
    id: 'grp_investment',
    category: 'Financial Scam',
    threatCategory: 'investment_fraud',
    title: 'Guaranteed Return & Risk-Free Investment Claims',
    whyItMatters: 'Financial regulations prohibit promising guaranteed profits. High returns paired with zero risk are the hallmark of Ponzi schemes, rug pulls, and fake trading platforms.',
    severity: 'high',
    patterns: [
      {
        regex: /\b(guaranteed (?:[0-9]+% )?(?:return|returns|profit|income|payout)|100% (?:risk[- ]free|guaranteed)|double your (?:money|bitcoin|crypto|investment))\b/i,
        label: 'Guaranteed Profit Assurance',
        description: 'Unrealistic promise of risk-free investment multiplication.',
        weight: 35,
      },
      {
        regex: /\b(crypto (?:investment|trading bot|automated trading)|passive daily income|mining pool return|insider trading tip|send [0-9.]+ (?:btc|eth|sol))\b/i,
        label: 'Cryptocurrency Multiplication Scheme',
        description: 'Solicitation for cryptocurrency deposit into private or unverified schemes.',
        weight: 25,
      },
    ],
  },

  // 5. Fake Recruitment & Work-From-Home Scams
  {
    id: 'grp_recruitment',
    category: 'Recruitment Fraud',
    threatCategory: 'recruitment_scam',
    title: 'Fake Job Offer & Unvetted Hiring Ploy',
    whyItMatters: 'Employment scams promise high compensation for trivial tasks, bypass standard interview processes, and eventually demand fees for "equipment", "background checks", or "training packages".',
    severity: 'high',
    patterns: [
      {
        regex: /\b(no interview needed|instant hiring|daily payout of \$[0-9]+|\$[0-9]{2,4}\/day for simple tasks|part[- ]time remote assistant)\b/i,
        label: 'Unrealistic Employment Compensation',
        description: 'Disproportionately high pay offered without standard credential verification.',
        weight: 25,
      },
      {
        regex: /\b(?:pay for|purchase|buy) (?:your )?(?:background check|home office equipment|equipment|starter kit|training kit|id badge)\b/i,
        label: 'Equipment / Onboarding Fee Extraction',
        description: 'Candidate required to pay money upfront to receive employment materials.',
        weight: 35,
      },
      {
        regex: /\b(contact our hr on telegram|message our recruiter on whatsapp|reach out to @[a-z0-9_]+ on telegram)\b/i,
        label: 'Off-Platform Recruiter Redirection',
        description: 'Routing job applicants away from verified corporate domains to encrypted anonymous messaging apps.',
        weight: 25,
      },
    ],
  },

  // 6. Fake Lottery, Inheritance & Prize Announcements
  {
    id: 'grp_prizes',
    category: 'Prize Lure',
    threatCategory: 'advance_fee_scam',
    title: 'Unsolicited Lottery, Prize, or Inheritance Notice',
    whyItMatters: 'You cannot win a contest or lottery you never entered. These pretexts exist purely to collect personal identity documents or extract "tax/clearance" fees.',
    severity: 'high',
    patterns: [
      {
        regex: /\b(congratulations you (have )?won|selected as (the|a) lucky winner|unclaimed (inheritance|funds|consignment|prize)|won \$[0-9,]+( million)?)\b/i,
        label: 'Fabricated Lottery/Prize Notification',
        description: 'Announcement of unearned windfall wealth or lottery selection.',
        weight: 30,
      },
      {
        regex: /\b(claim your (reward|prize|inheritance|funds) (now|before it expires)|spin the wheel)\b/i,
        label: 'Reward Claim Lure',
        description: 'Urging victim to initiate claim procedures for fictitious assets.',
        weight: 20,
      },
    ],
  },

  // 7. Brand & Authority Impersonation
  {
    id: 'grp_impersonation',
    category: 'Brand Impersonation',
    threatCategory: 'brand_impersonation',
    title: 'Authority or Commercial Brand Impersonation',
    whyItMatters: 'Scammers borrow trust from known brands (courier delivery, payment processors, tech support) to lower the victim\'s psychological defenses.',
    severity: 'medium',
    patterns: [
      {
        regex: /\b(usps delivery failed|fedex package pending|dhl parcel on hold|unpaid delivery fee|customs clearance required for parcel)\b/i,
        label: 'Parcel Delivery Smishing Pretext',
        description: 'Impersonation of courier service claiming a package cannot be delivered without fee payment.',
        weight: 25,
      },
      {
        regex: /\b(geek squad auto[- ]renewal|norton subscription renewed|mcafee total protection invoice|billing support at 1-8[0-9]{2})\b/i,
        label: 'Tech Support Invoice Fraud',
        description: 'Fake high-value renewal invoice designed to trigger panicked phone calls.',
        weight: 30,
      },
      {
        regex: /\b(paypal fraud department|bank of america security alert|wells fargo fraud prevention|chase security team)\b/i,
        label: 'Financial Institution Pretext',
        description: 'Impersonation of banking fraud monitoring division.',
        weight: 25,
      },
    ],
  },
];

export interface MessageAnalysisOutput {
  heuristicScore: number; // 0 to 100
  indicators: DetectedIndicator[];
  highlightSpans: HighlightSpan[];
  suggestedCategory: ThreatCategory;
  compoundTriggersFound: string[];
}

export function analyzeMessageHeuristics(text: string): MessageAnalysisOutput {
  const indicators: DetectedIndicator[] = [];
  const highlightSpans: HighlightSpan[] = [];
  const categoryScores: Record<ThreatCategory, number> = {
    phishing_url: 0,
    credential_harvesting: 0,
    advance_fee_scam: 0,
    investment_fraud: 0,
    recruitment_scam: 0,
    urgency_extortion: 0,
    brand_impersonation: 0,
    legitimate: 0,
    unknown: 0,
  };

  let totalScore = 0;
  const activatedGroups = new Set<string>();

  for (const group of MESSAGE_RULE_GROUPS) {
    for (const pattern of group.patterns) {
      const match = text.match(pattern.regex);
      if (match && match.index !== undefined) {
        totalScore += pattern.weight;
        activatedGroups.add(group.id);
        categoryScores[group.threatCategory] = (categoryScores[group.threatCategory] || 0) + pattern.weight;

        indicators.push({
          id: `${group.id}_${indicators.length}`,
          category: group.category,
          title: pattern.label,
          description: pattern.description,
          whyItMatters: group.whyItMatters,
          severity: group.severity,
          evidenceSnippet: match[0],
          ruleType: 'nlp_heuristic',
        });

        // Add highlight span
        highlightSpans.push({
          start: match.index,
          end: match.index + match[0].length,
          text: match[0],
          severity: group.severity,
          label: pattern.label,
        });
      }
    }
  }

  // Combinatorial Compound Boosters:
  // e.g. Urgency + OTP solicitation = critical credential harvesting attack
  const compoundTriggers: string[] = [];
  if (activatedGroups.has('grp_credentials') && activatedGroups.has('grp_urgency_threats')) {
    totalScore += 20;
    compoundTriggers.push('Urgent Coercion + Credential/OTP Solicitation');
    indicators.push({
      id: 'compound_urgency_credentials',
      category: 'Compound Threat Pattern',
      title: 'High-Velocity Credential Theft Combination',
      description: 'The message pairs coercive urgency/account sanctions with requests for credentials or OTP passcodes.',
      whyItMatters: 'This pairing is the classic signature of account takeover attacks designed to capture live 2FA tokens before victim verification.',
      severity: 'critical',
      ruleType: 'structure',
    });
  }

  if (activatedGroups.has('grp_recruitment') && activatedGroups.has('grp_advance_fee')) {
    totalScore += 20;
    compoundTriggers.push('Recruitment Offer + Upfront Payment Demand');
    indicators.push({
      id: 'compound_recruitment_fee',
      category: 'Compound Threat Pattern',
      title: 'Employment Fee Extraction Combination',
      description: 'Unverified job offer accompanied by upfront equipment or background check fee.',
      whyItMatters: 'Legitimate employers provide standard equipment and absorb onboarding costs. Charging applicants upfront is fraudulent.',
      severity: 'critical',
      ruleType: 'structure',
    });
  }

  if (activatedGroups.has('grp_prizes') && activatedGroups.has('grp_advance_fee')) {
    totalScore += 20;
    compoundTriggers.push('Prize Announcement + Advance Processing Fee');
    indicators.push({
      id: 'compound_prize_fee',
      category: 'Compound Threat Pattern',
      title: 'Advance-Fee Prize Extraction',
      description: 'Prize/lottery winning notification that demands a clearance or processing fee.',
      whyItMatters: 'True winnings never require pre-payment of taxes or clearance via gift cards or wire transfers.',
      severity: 'critical',
      ruleType: 'structure',
    });
  }

  // Compound booster for multi-claim high yield investment fraud
  const invGroup = MESSAGE_RULE_GROUPS.find(g => g.id === 'grp_investment');
  const invMatches = invGroup ? invGroup.patterns.filter(p => p.regex.test(text)).length : 0;
  if (invMatches >= 2) {
    totalScore += 25;
    compoundTriggers.push('Multi-Claim Investment Fraud (Guaranteed Return + Zero Risk)');
    indicators.push({
      id: 'compound_investment_fraud',
      category: 'Compound Threat Pattern',
      title: 'High-Yield Investment Fraud (HYIP) Signature',
      description: 'Message pairs unrealistic guaranteed returns with risk-free assertions and cryptocurrency transfer lures.',
      whyItMatters: 'Financial markets never offer guaranteed zero-risk high returns. This combination is the textbook hallmark of Ponzi schemes.',
      severity: 'critical',
      ruleType: 'structure',
    });
  }

  // Determine top category
  let topCategory: ThreatCategory = 'unknown';
  let maxCatScore = 0;
  for (const [cat, score] of Object.entries(categoryScores)) {
    if (score > maxCatScore) {
      maxCatScore = score;
      topCategory = cat as ThreatCategory;
    }
  }

  const clampedScore = Math.min(100, Math.max(0, totalScore));

  return {
    heuristicScore: clampedScore,
    indicators,
    highlightSpans,
    suggestedCategory: topCategory,
    compoundTriggersFound: compoundTriggers,
  };
}
