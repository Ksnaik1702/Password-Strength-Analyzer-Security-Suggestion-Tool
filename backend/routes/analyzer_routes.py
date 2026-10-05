"""
Analyzer API Routes
Handles /api/analyze requests with strict in-memory execution and zero password persistence.
"""

from fastapi import APIRouter, HTTPException
from backend.models.schemas import AnalyzeRequest, AnalyzeResponse
from backend.services.password_analyzer import analyze_password
from backend.database import record_analysis_metadata

router = APIRouter(prefix="/api", tags=["Analyzer"])

@router.post("/analyze", response_model=AnalyzeResponse)
def handle_analyze(req: AnalyzeRequest):
    """
    Analyzes password strength in-memory and returns structured findings and suggestions.
    
    PRIVACY RULES:
    1. Input password is processed transiently in RAM.
    2. Input password is NOT logged to console or logs.
    3. Input password is NOT written to database.
    4. Input password is NOT echoed in API response.
    5. Anonymous mathematical metrics (score, length, finding types) are recorded for dashboard.
    """
    try:
        context = {
            "first_name": req.first_name,
            "birth_year": req.birth_year,
            "organization": req.organization
        }
        result = analyze_password(req.password, personal_context=context)

        # Record anonymous metadata (omits raw password completely)
        if len(req.password) > 0:
            try:
                record_analysis_metadata(result)
            except Exception:
                pass  # Telemetry failure should never break live analysis

        return result
    except Exception as e:
        # Never leak password in error details
        raise HTTPException(status_code=500, detail="Internal analysis error.")
