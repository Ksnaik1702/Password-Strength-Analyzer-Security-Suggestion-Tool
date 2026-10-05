"""
API Endpoint Integration Tests
Validates all FastAPI routes:
- POST /api/analyze
- POST /api/generate
- POST /api/policy/check
- POST /api/hashing/demonstrate
- POST /api/hashing/verify
- GET  /api/dashboard/stats
- GET  /api/health
"""

import pytest
from starlette.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"

def test_api_analyze_transient():
    payload = {
        "password": "Password123!",
        "first_name": "Demo",
        "birth_year": "1990",
        "organization": "TestOrg"
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "score" in data
    assert "classification" in data
    assert "findings" in data
    assert "suggestions" in data
    assert "metrics" in data
    # Confirm password itself is NOT echoed back in the response
    assert "password" not in data

def test_api_generate_complex():
    payload = {
        "mode": "complex",
        "length": 24,
        "include_upper": True,
        "include_lower": True,
        "include_digits": True,
        "include_symbols": True
    }
    res = client.post("/api/generate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "complex"
    assert len(data["generated_password"]) == 24
    assert data["bits_estimate"] > 100

def test_api_generate_passphrase():
    payload = {
        "mode": "passphrase",
        "words_count": 5,
        "separator": "-"
    }
    res = client.post("/api/generate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "passphrase"
    words = data["generated_password"].split("-")
    assert len(words) == 5

def test_api_policy_check():
    payload = {
        "password": "Short",
        "min_length": 12,
        "max_length": 128,
        "disallow_common": True
    }
    res = client.post("/api/policy/check", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["policy_passed"] is False
    assert data["status"] == "POLICY FAIL"

def test_api_hashing_demo_and_verify():
    secret = "DemoSecretToHash123!"
    res_demo = client.post("/api/hashing/demonstrate", json={"password": secret})
    assert res_demo.status_code == 200
    demo_data = res_demo.json()
    stored_hash = demo_data["stored_hash_format"]

    # Valid verify
    res_v1 = client.post("/api/hashing/verify", json={"password": secret, "stored_hash_format": stored_hash})
    assert res_v1.status_code == 200
    assert res_v1.json()["is_valid"] is True

    # Invalid verify
    res_v2 = client.post("/api/hashing/verify", json={"password": "WrongPassword!", "stored_hash_format": stored_hash})
    assert res_v2.status_code == 200
    assert res_v2.json()["is_valid"] is False

def test_api_dashboard_stats():
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_analyses" in data
    assert "classifications" in data
    assert "weakness_frequency" in data
    assert "length_distribution" in data
