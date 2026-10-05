"""
Password Generator API Routes
Handles /api/generate requests using cryptographically secure secrets.
"""

from fastapi import APIRouter
from backend.models.schemas import GenerateRequest, GenerateResponse
from backend.services.password_generator import generate_complex_password, generate_passphrase
from backend.services.entropy_estimator import estimate_theoretical_entropy

router = APIRouter(prefix="/api", tags=["Generator"])

@router.post("/generate", response_model=GenerateResponse)
def handle_generate(req: GenerateRequest):
    """
    Generates high-entropy passwords or passphrases.
    Generated credentials are never stored.
    """
    if req.mode == "passphrase":
        password = generate_passphrase(words_count=req.words_count, separator=req.separator)
        # Diceware wordlist of ~80 words: log2(80) ~ 6.32 bits per word
        bits = round(req.words_count * 6.32, 1)
    else:
        password = generate_complex_password(
            length=req.length,
            include_upper=req.include_upper,
            include_lower=req.include_lower,
            include_digits=req.include_digits,
            include_symbols=req.include_symbols
        )
        pool = 0
        if req.include_lower: pool += 26
        if req.include_upper: pool += 26
        if req.include_digits: pool += 10
        if req.include_symbols: pool += 32
        entropy_data = estimate_theoretical_entropy(req.length, max(pool, 2))
        bits = entropy_data["entropy_bits"]

    return {
        "mode": req.mode,
        "generated_password": password,
        "length": len(password),
        "bits_estimate": bits
    }
