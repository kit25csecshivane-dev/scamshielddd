import datetime
from fastapi import APIRouter, HTTPException
from backend.app.models.schemas import (
    AnalysisRequest,
    AnalysisResponse,
    FeedbackRequest,
    FeedbackResponse,
    ModelInfoResponse,
    HealthResponse
)
from backend.app.services.analyzer import analyze_content
from backend.app.services.ml_engine import MODEL_METADATA

router = APIRouter()

feedback_storage = []

@router.get("/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "healthy",
        "service": "PhishGuard Threat Analyzer API (FastAPI)",
        "version": "1.0.0",
        "mode": "hybrid_ml_lexical",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@router.get("/model-info", response_model=ModelInfoResponse)
def model_info():
    return {
        "modelName": MODEL_METADATA["name"],
        "version": "1.4.0",
        "algorithm": MODEL_METADATA["algorithm"],
        "vectorizer": MODEL_METADATA["vectorizer"],
        "vocabularySize": MODEL_METADATA["vocabularySize"],
        "trainedClasses": [
            "Deceptive Phishing URL",
            "Credential Harvesting",
            "Advance-Fee Scam",
            "Investment Fraud",
            "Recruitment Scam",
            "Urgency & Extortion",
            "Brand Impersonation",
            "Benign Communication"
        ],
        "metrics": MODEL_METADATA["metrics"],
        "baselineAvailable": True,
        "scoringWeights": {
            "mlTextWeight": 0.45,
            "lexicalRuleWeight": 0.45,
            "compoundContextMultiplier": 0.10
        }
    }

@router.post("/analyze", response_model=AnalysisResponse)
def analyze_endpoint(request: AnalysisRequest):
    if len(request.content) > 25000:
        raise HTTPException(status_code=413, detail="Payload Too Large: Content exceeds 25,000 characters limit.")

    result = analyze_content(request.content, request.inputType or "auto")
    return result

@router.post("/feedback", response_model=FeedbackResponse)
def feedback_endpoint(request: FeedbackRequest):
    record_id = f"fb_{len(feedback_storage) + 1}"
    feedback_storage.append({
        "recordId": record_id,
        "analysisId": request.analysisId,
        "userAssessment": request.userAssessment,
        "comments": request.comments
    })
    return {
        "success": True,
        "message": "Feedback recorded safely without sensitive content.",
        "recordId": record_id
    }
