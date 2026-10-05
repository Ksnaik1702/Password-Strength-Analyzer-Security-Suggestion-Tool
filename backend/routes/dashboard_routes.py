"""
Dashboard & Analytics API Routes
Serves anonymous aggregate statistics and distribution metrics.
"""

from fastapi import APIRouter
from backend.database import get_dashboard_statistics

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats")
def handle_dashboard_stats():
    """
    Returns aggregate charts and counts. Zero passwords or hashes are exposed.
    """
    return get_dashboard_statistics()
