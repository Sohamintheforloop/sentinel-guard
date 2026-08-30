from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import joblib
import os
from app.core.extractor import extract_features

app = FastAPI(title="SentinelGuard Prediction Engine", version="1.0.0")

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models/rf_model.joblib")
model = joblib.load(MODEL_PATH)

class InspectRequest(BaseModel):
    url: str

class InspectResponse(BaseModel):
    url: str
    risk_score: int
    decision: str  # "ALLOW", "WARN", "BLOCK"
    confidence: float

@app.post("/api/v1/inspect", response_model=InspectResponse)
async def inspect_url(payload: InspectRequest):
    try:
        features = extract_features(payload.url)
        prob_malicious = float(model.predict_proba(features)[0][1])
        risk_score = int(prob_malicious * 100)

        if risk_score >= 75:
            decision = "BLOCK"
        elif risk_score >= 40:
            decision = "WARN"
        else:
            decision = "ALLOW"

        return InspectResponse(
            url=payload.url,
            risk_score=risk_score,
            decision=decision,
            confidence=round(prob_malicious, 4)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))