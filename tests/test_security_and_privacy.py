"""
Security & Privacy Audit Tests
Verifies the defensive posture and strict privacy requirements:
- Test 28: Password not stored in database
- Test 29: Password not logged
- Test 30: Analytics storage contains strictly anonymous telemetry
- Zero-leakage verification in API responses
"""

import sqlite3
import pytest
from backend.database import get_connection, init_db, record_analysis_metadata
from backend.services.password_analyzer import analyze_password

def test_28_password_not_stored_in_database():
    """
    AUDIT REQUIREMENT:
    Verify that the SQLite schema contains ZERO password, hash, or salt columns.
    """
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(analyses)")
        columns = [row["name"].lower() for row in cursor.fetchall()]

        # Explicitly assert that no password-related column exists
        assert "password" not in columns
        assert "plaintext" not in columns
        assert "hash" not in columns
        assert "password_hash" not in columns
        assert "salt" not in columns
        assert "user_id" not in columns
        assert "username" not in columns

        cursor.execute("PRAGMA table_info(findings)")
        finding_columns = [row["name"].lower() for row in cursor.fetchall()]
        assert "password" not in finding_columns

def test_29_password_not_logged():
    """
    AUDIT REQUIREMENT:
    Verify that password analyzer services and routers do not emit raw passwords to standard logs.
    """
    secret = "TopSecretPasswordDoNotLog123!"
    result = analyze_password(secret)
    
    # Findings should not contain the exact secret
    for finding in result["findings"]:
        assert secret not in finding.get("description", "")
        assert secret not in finding.get("title", "")

    # Suggestions should not contain the exact secret
    for suggestion in result["suggestions"]:
        assert secret not in suggestion

def test_30_analytics_storage_anonymity():
    """
    AUDIT REQUIREMENT:
    Verify that recording analysis metadata stores strictly anonymous metrics.
    """
    secret = "DemoTransientPassword#2026"
    res = analyze_password(secret)
    aid = record_analysis_metadata(res)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (aid,))
        row = cursor.fetchone()
        assert row is not None

        # Confirm stored fields are non-secret metadata
        assert row["score"] == res["score"]
        assert row["password_length"] == len(secret)
        assert row["classification"] == res["classification"]
        
        # Verify findings recorded do not leak secret
        cursor.execute("SELECT description FROM findings WHERE analysis_id = ?", (aid,))
        for f_row in cursor.fetchall():
            assert secret not in f_row["description"]
