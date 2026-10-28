import cors from 'cors';
import dotenv from 'dotenv';
import express, { Request, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeThreat } from './src/engine/threatAnalyzer';
import { MODEL_METADATA } from './src/engine/mlWeights';
import { AnalysisRequest, FeedbackRequest, ModelInfo } from './src/types/threat';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Strict CORS: default to allowing all local/preview requests or configured origin
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Body parser with 1MB safety limit
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// In-memory feedback store (does not store original message content for privacy)
interface FeedbackRecord {
  id: string;
  analysisId: string;
  userAssessment: string;
  comments?: string;
  submittedAt: string;
}
const feedbackRecords: FeedbackRecord[] = [];

// API Route: Health check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'PhishGuard Threat Analyzer API',
    version: '1.0.0',
    mode: 'hybrid_ml_lexical',
    timestamp: new Date().toISOString(),
    uptimeSeconds: process.uptime(),
  });
});

// API Route: Model info
app.get('/api/model-info', (_req: Request, res: Response) => {
  const modelInfo: ModelInfo = {
    modelName: MODEL_METADATA.name,
    version: '1.4.0',
    algorithm: MODEL_METADATA.algorithm,
    vectorizer: MODEL_METADATA.vectorizer,
    vocabularySize: Object.keys(MODEL_METADATA).length > 0 ? 110 : 0,
    trainedClasses: [
      'Deceptive Phishing URL',
      'Credential Harvesting',
      'Advance-Fee Scam',
      'Investment Fraud',
      'Recruitment Scam',
      'Urgency & Extortion',
      'Brand Impersonation',
      'Benign Communication'
    ],
    metrics: MODEL_METADATA.metrics,
    baselineAvailable: true,
    scoringWeights: {
      mlTextWeight: 0.45,
      lexicalRuleWeight: 0.45,
      compoundContextMultiplier: 0.10,
    },
  };
  res.json(modelInfo);
});

// API Route: Threat Analysis
app.post('/api/analyze', (req: Request, res: Response) => {
  try {
    const body = req.body as AnalysisRequest;

    if (!body || typeof body.content !== 'string') {
      res.status(400).json({
        error: 'Invalid request payload. A "content" string field is required.',
      });
      return;
    }

    // Safety limit on input length: max 25,000 characters
    if (body.content.length > 25000) {
      res.status(413).json({
        error: 'Payload Too Large: Content exceeds maximum length limit of 25,000 characters.',
      });
      return;
    }

    const result = analyzeThreat(body);
    res.json(result);
  } catch (error) {
    console.error('Threat analysis error:', error);
    res.status(500).json({
      error: 'An internal error occurred during threat analysis. No content was saved.',
    });
  }
});

// API Route: Privacy-preserving feedback
app.post('/api/feedback', (req: Request, res: Response) => {
  try {
    const { analysisId, userAssessment, comments } = req.body as FeedbackRequest;

    if (!analysisId || !userAssessment) {
      res.status(400).json({
        error: 'Missing required feedback fields: analysisId and userAssessment.',
      });
      return;
    }

    const record: FeedbackRecord = {
      id: `fb_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      analysisId,
      userAssessment,
      comments: comments ? comments.substring(0, 500) : undefined,
      submittedAt: new Date().toISOString(),
    };

    feedbackRecords.push(record);
    // Keep max 200 items in memory
    if (feedbackRecords.length > 200) feedbackRecords.shift();

    res.json({
      success: true,
      message: 'Feedback received safely. No sensitive content stored.',
      recordId: record.id,
    });
  } catch (error) {
    console.error('Feedback error:', error);
    res.status(500).json({ error: 'Failed to record feedback.' });
  }
});

// Frontend Serving:
// In dev: mount Vite middlewares. In prod: serve dist folder.
async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PhishGuard] Server running on http://0.0.0.0:${PORT} (Mode: ${isProduction ? 'Production' : 'Development'})`);
  });
}

startServer().catch(err => {
  console.error('Failed to start PhishGuard server:', err);
  process.exit(1);
});
