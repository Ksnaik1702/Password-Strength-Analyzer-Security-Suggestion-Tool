"""
Pydantic Data Models & Request/Response Schemas
Strictly defines API contracts with privacy constraints.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class AnalyzeRequest(BaseModel):
    password: str = Field(..., max_length=256, description="Password candidate to analyze transiently in memory.")
    first_name: Optional[str] = Field(None, max_length=64, description="Optional context attribute for overlap check.")
    birth_year: Optional[str] = Field(None, max_length=10, description="Optional birth year for overlap check.")
    organization: Optional[str] = Field(None, max_length=64, description="Optional company or university name.")

class FindingDetail(BaseModel):
    type: str
    severity: str
    status: str
    title: str
    description: str

class AnalyzeResponse(BaseModel):
    score: int
    classification: str
    findings: List[FindingDetail]
    suggestions: List[str]
    metrics: Dict[str, Any]
    entropy_info: Dict[str, Any]

class GenerateRequest(BaseModel):
    mode: str = Field("complex", description="'complex' or 'passphrase'")
    length: int = Field(16, ge=8, le=64)
    include_upper: bool = True
    include_lower: bool = True
    include_digits: bool = True
    include_symbols: bool = True
    words_count: int = Field(4, ge=3, le=8)
    separator: str = "-"

class GenerateResponse(BaseModel):
    mode: str
    generated_password: str
    length: int
    bits_estimate: float

class PolicyCheckRequest(BaseModel):
    password: str
    min_length: int = 12
    max_length: int = 128
    disallow_common: bool = True
    first_name: Optional[str] = None
    birth_year: Optional[str] = None
    organization: Optional[str] = None

class PolicyCheckResponse(BaseModel):
    policy_passed: bool
    status: str
    failures: List[str]
    checks: List[Dict[str, Any]]
    educational_note: str

class HashingDemoRequest(BaseModel):
    password: str = Field(default="DemoSyntheticPass123!")

class HashingVerifyRequest(BaseModel):
    password: str
    stored_hash_format: str
