"""api.py - FastAPI Backend for VIT Phishing Awareness & Detection

Serves the machine learning and heuristic detection pipeline for the Chrome Extension
and external integrations. Ready for immediate deployment on Render (render.com).
"""

import os
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from src.phishing_core import PhishingDetector, defang_url, find_urls

# Initialize FastAPI application
app = FastAPI(
    title="VIT Phishing Awareness & Detection API",
    description="Explainable AI API for detecting phishing communications and analyzing threat indicators.",
    version="1.0.0"
)

# Enable CORS for Chrome Extensions and web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load machine learning models on startup
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
detector = PhishingDetector(model_dir=MODEL_DIR)

class PredictRequest(BaseModel):
    text: Optional[str] = Field(default="", description="Email body or web page content")
    subject: Optional[str] = Field(default="", description="Email subject line or page title")
    sender: Optional[str] = Field(default=None, description="Sender display name and email address")
    url: Optional[str] = Field(default=None, description="Specific URL to inspect")

class DefangRequest(BaseModel):
    url: str = Field(..., description="Raw URL to defang")

class SignalItem(BaseModel):
    signal_name: str
    triggered: bool
    weight: float
    reason: str

class PredictResponse(BaseModel):
    status: str = "success"
    probability: float
    risk_level: str
    risk_color: str
    verdict_summary: str
    defanged_urls: List[str]
    strongest_signals: List[str]
    signals: List[SignalItem]

@app.get("/")
def read_root():
    """Health check and service status."""
    return {
        "status": "online",
        "service": "VIT Phishing Detection & Awareness API",
        "version": "1.0.0",
        "models_loaded": detector.classifier is not None,
        "docs_url": "/docs"
    }

@app.get("/health")
def health_check():
    """Standard health check endpoint for cloud monitoring."""
    return {"status": "healthy"}

@app.post("/predict", response_model=PredictResponse)
def predict_threat(payload: PredictRequest):
    """Analyzes text, subject, sender, and optional URL for phishing indicators."""
    full_text = (payload.text or "").strip()
    if payload.url and payload.url not in full_text:
        full_text = f"{full_text}\n{payload.url}".strip()

    if not full_text and not payload.subject and not payload.sender:
        raise HTTPException(
            status_code=400,
            detail="At least one of 'text', 'subject', 'sender', or 'url' must be provided."
        )

    try:
        res = detector.predict(
            subject=payload.subject or "",
            body=full_text,
            sender=payload.sender
        )

        signals_list = [
            SignalItem(
                signal_name=s["signal_name"],
                triggered=s["triggered"],
                weight=s["weight"],
                reason=s["reason"]
            )
            for s in res["xai"]["signals_table"]
        ]

        return PredictResponse(
            status="success",
            probability=round(float(res["probability"]), 4),
            risk_level=res["risk_label"],
            risk_color=res["risk_color"],
            verdict_summary=res["xai"]["verdict_summary"],
            defanged_urls=res["defanged_urls"],
            strongest_signals=res["strongest_signals"],
            signals=signals_list
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

@app.post("/defang")
def defang_endpoint(payload: DefangRequest):
    """Safely defangs a URL without network resolution."""
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return {
        "raw_url": raw_url,
        "defanged_url": defang_url(raw_url)
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)
