"""
Hashing Demonstration API Routes
Provides interactive endpoints for demonstrating password hashing, salts, key stretching,
and constant-time hash verification using synthetic test inputs.
"""

from fastapi import APIRouter
from backend.models.schemas import HashingDemoRequest, HashingVerifyRequest
from backend.services.hashing_demo import demonstrate_hashing, verify_password_hash

router = APIRouter(prefix="/api/hashing", tags=["Hashing Demo"])

@router.post("/demonstrate")
def handle_hashing_demo(req: HashingDemoRequest):
    """
    Computes a 16-byte random salt and derives PBKDF2-HMAC-SHA256 hash.
    For educational purposes only.
    """
    return demonstrate_hashing(req.password)

@router.post("/verify")
def handle_hashing_verify(req: HashingVerifyRequest):
    """
    Verifies a password against a stored format using constant-time comparison.
    """
    is_valid = verify_password_hash(req.password, req.stored_hash_format)
    return {
        "is_valid": is_valid,
        "status": "MATCH" if is_valid else "MISMATCH",
        "description": "Password matches hash verification." if is_valid else "Incorrect password."
    }
