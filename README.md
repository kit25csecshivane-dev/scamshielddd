# PhishGuard — AI-Powered Phishing and Scam Detection with Explainable Threat Analysis

PhishGuard is an explainable threat intelligence and triage system engineered to detect phishing URLs, smishing messages, credential-harvesting attacks, advance-fee scams, recruitment fraud, and cryptocurrency schemes.

The system combines air-gapped lexical URL decomposition, NLP heuristics, and an L2-regularized Logistic Regression classifier with sublinear TF-IDF vectorization. Rather than acting as a black box, PhishGuard exposes the exact observable evidence, n-gram log-odds feature contributions, and contextual security rationales for every risk determination.

---

## 1. System Architecture

```
phishguard/
├── src/                          # Frontend Application (React 19 + TypeScript + Vite)
│   ├── components/               # Gauges, Evidence Panels, Highlighted Text, Modals
│   ├── engine/                   # TypeScript Implementation of ML & Heuristic Analyzer
│   ├── pages/                    # Dashboard, Methodology, Specifications
│   └── types/                    # Threat, Indicator, Metric interfaces
├── server.ts                     # Full-Stack Express Server (Port 3000 in AI Studio)
├── backend/                      # Production Python Backend (FastAPI)
│   ├── app/
│   │   ├── main.py               # FastAPI App & Middleware
│   │   ├── api/endpoints.py      # REST Endpoints (/health, /analyze, /model-info, /feedback)
│   │   ├── services/             # URL Engine, Message Heuristics, ML Inference
│   │   └── models/schemas.py     # Pydantic Request & Response Schemas
│   ├── ml/
│   │   ├── dataset.py            # Development and evaluation datasets
│   │   ├── train.py              # Scikit-learn TF-IDF + Logistic Regression trainer
│   │   └── evaluate.py           # Evaluation script with confusion matrix & false-negative rates
│   ├── tests/                    # Pytest and Unittest test suite
│   ├── requirements.txt          # Python dependencies
│   └── Dockerfile                # Containerized backend deployment
├── package.json
└── README.md
```

---

## 2. Risk Score & Threat Classification Scheme

PhishGuard assigns a deterministic triage score from **0 to 100**, categorized into four standard risk bands:

- **0 – 30 (Low Risk):** Benign correspondence or verified institutional top-level domains (.gov, .edu).
- **31 – 60 (Medium Risk):** Contextually ambiguous phrasing, missing security headers, or isolated indicators.
- **61 – 80 (High Risk):** Elevated signals of credential solicitation, deceptive subdomains, or unverified hiring schemes.
- **81 – 100 (Critical Risk):** Severe compound attacks (e.g. IP-based hostnames with login keywords, or urgent threats combined with OTP harvesting).
- **Unknown:** Returned when input contains insufficient diagnostic signals (< 3 characters) or unsupported formats.

### Scoring Fusion Formula
```
Score_URL     = clamp(0.50 · Lexical_Score + 0.40 · ML_Score + Critical_Bonus, 0, 100)
Score_Message = clamp(0.45 · Heuristic_Score + 0.45 · ML_Score + Compound_Multiplier, 0, 100)
```

---

## 3. Step-by-Step Operations Guide

### 1. Installing Dependencies
```bash
# Frontend & Express Full-Stack Server
npm install

# Python Backend (if running standalone FastAPI backend)
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ..
```

### 2. Running Locally
```bash
# Start AI Studio Full-Stack Server (runs frontend + API on port 3000)
npm run dev
```

### 3. Training the Machine Learning Model
```bash
# Run the scikit-learn training script on the labeled corpus:
python3 -m backend.ml.train --output backend/ml/model_weights.json
```

### 4. Running Automated Tests
```bash
# Run Python backend unit tests:
python3 -m unittest backend/tests/test_analyzer.py

# Or using pytest:
pytest backend/tests/
```

### 5. Building the Frontend
```bash
npm run build
```

### 6. Starting the Standalone Python FastAPI Backend
```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 7. Deploying the Frontend (Static Host / Vercel / Cloudflare Pages)
```bash
# Set backend URL environment variable:
export VITE_API_BASE_URL="https://your-backend-api.com"
npm run build
# Deploy dist/ folder to static hosting
```

### 8. Deploying the Backend (Docker / Cloud Run / Render)
```bash
cd backend
docker build -t phishguard-api .
docker run -p 8000:8000 -e PORT=8000 phishguard-api
```

### 9. Configuring Environment Variables
Create `.env` using `.env.example`:
```env
PORT=3000
NODE_ENV=production
ALLOWED_ORIGINS=http://localhost:3000,https://my-app.run.app
ENABLE_LOCAL_SQLITE_HISTORY=false
```

### 10. Verifying the Live Deployment
```bash
# 1. Health check verification
curl -s http://localhost:3000/api/health

# 2. Test analysis check
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "URGENT: Verify your password now within 24 hours.", "inputType": "sms"}'
```

---

## 4. Key Security & Privacy Principles

1. **Air-Gapped Lexical Inspection:** PhishGuard never makes network requests to, pings, or opens submitted URLs.
2. **Zero Password / OTP Retention:** Sensitive input content is processed in volatile memory only and is discarded immediately after feature extraction.
3. **Privacy-Preserving History:** Local scan history is disabled by default. When enabled, records are saved strictly in the user's browser.
4. **HTTPS Axiom:** HTTPS proves only that data in transit is encrypted; it is never treated as proof that a domain is legitimate.
