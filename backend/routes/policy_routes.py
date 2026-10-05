"""
Policy Checker API Routes
Validates password candidates against NIST SP 800-63B policy configurations.
"""

from fastapi import APIRouter
from backend.models.schemas import PolicyCheckRequest, PolicyCheckResponse
from backend.services.policy_checker import check_policy_compliance

router = APIRouter(prefix="/api/policy", tags=["Policy"])

@router.post("/check", response_model=PolicyCheckResponse)
def handle_policy_check(req: PolicyCheckRequest):
    """
    Evaluates policy compliance (pass/fail) independently of strength score.
    """
    context = {}
    if req.first_name: context["first_name"] = req.first_name
    if req.birth_year: context["birth_year"] = req.birth_year
    if req.organization: context["organization"] = req.organization

    result = check_policy_compliance(
        password=req.password,
        min_length=req.min_length,
        max_length=req.max_length,
        disallow_common=req.disallow_common,
        personal_context=context if context else None
    )
    return result
