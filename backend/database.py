"""
Privacy-Safe Database Module
Manages SQLite storage for anonymous aggregate metrics and statistics.

CRITICAL PRIVACY & SECURITY DESIGN:
- Zero password persistence: Plaintext passwords, hashes, salts, and user identities
  are NEVER stored in this database.
- Only safe mathematical metadata (length, score, classification, weakness counts)
  are recorded for educational awareness dashboard visualizations.
"""

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "analytics.db"

def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes tables if they do not exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        cursor = conn.cursor()
        
        # Table 1: ANALYSES (Strictly anonymous metadata, NO password column)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                analysis_id TEXT PRIMARY KEY,
                score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                password_length INTEGER NOT NULL,
                unique_character_ratio REAL NOT NULL,
                weakness_count INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Table 2: FINDINGS (Categorical weakness types, NO plaintext passwords)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id)
            )
        """)
        conn.commit()

def record_analysis_metadata(analysis_result: Dict[str, Any]) -> str:
    """
    Saves anonymous analytical metrics. The submitted password itself is omitted completely.
    """
    analysis_id = str(uuid.uuid4())
    score = analysis_result["score"]
    classification = analysis_result["classification"]
    metrics = analysis_result.get("metrics", {})
    length = metrics.get("length", 0)
    unique_ratio = metrics.get("unique_character_ratio", 0.0)
    weakness_count = metrics.get("weakness_count", 0)
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analyses (
                analysis_id, score, classification, password_length,
                unique_character_ratio, weakness_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (analysis_id, score, classification, length, unique_ratio, weakness_count, now))

        # Record generic finding types
        for f in analysis_result.get("findings", []):
            if f.get("status") == "negative":
                # Ensure no sensitive substrings are saved in description
                desc = f.get("title", f.get("type", "Weakness"))
                cursor.execute("""
                    INSERT INTO findings (analysis_id, finding_type, severity, description)
                    VALUES (?, ?, ?, ?)
                """, (analysis_id, f.get("type", "unknown"), f.get("severity", "medium"), desc))

        conn.commit()
    return analysis_id

def get_dashboard_statistics() -> Dict[str, Any]:
    """
    Computes aggregate metrics for dashboard charts.
    """
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()

        # Total counts
        cursor.execute("SELECT COUNT(*), AVG(score) FROM analyses")
        row = cursor.fetchone()
        total_analyses = row[0] if row else 0
        avg_score = round(row[1], 1) if (row and row[1] is not None) else 0.0

        # Classification distribution
        cursor.execute("""
            SELECT classification, COUNT(*) as count 
            FROM analyses 
            GROUP BY classification
        """)
        class_counts = {r["classification"]: r["count"] for r in cursor.fetchall()}
        
        # Populate all standard classifications
        classifications = {
            "VERY WEAK": class_counts.get("VERY WEAK", 0),
            "WEAK": class_counts.get("WEAK", 0),
            "MODERATE": class_counts.get("MODERATE", 0),
            "STRONG": class_counts.get("STRONG", 0),
            "VERY STRONG": class_counts.get("VERY STRONG", 0)
        }

        # Weakness frequency
        cursor.execute("""
            SELECT finding_type, COUNT(*) as count 
            FROM findings 
            GROUP BY finding_type 
            ORDER BY count DESC 
            LIMIT 10
        """)
        weaknesses = [{"type": r["finding_type"], "count": r["count"]} for r in cursor.fetchall()]

        # Length distribution buckets
        cursor.execute("""
            SELECT 
                SUM(CASE WHEN password_length < 8 THEN 1 ELSE 0 END) as less_8,
                SUM(CASE WHEN password_length >= 8 AND password_length <= 11 THEN 1 ELSE 0 END) as range_8_11,
                SUM(CASE WHEN password_length >= 12 AND password_length <= 15 THEN 1 ELSE 0 END) as range_12_15,
                SUM(CASE WHEN password_length >= 16 THEN 1 ELSE 0 END) as range_16_plus
            FROM analyses
        """)
        len_row = cursor.fetchone()
        length_distribution = {
            "< 8 (Very Short)": len_row["less_8"] or 0,
            "8-11 (Short)": len_row["range_8_11"] or 0,
            "12-15 (Better)": len_row["range_12_15"] or 0,
            "16+ (Strong)": len_row["range_16_plus"] or 0
        }

        # Recent 10 analyses (safe metadata only)
        cursor.execute("""
            SELECT analysis_id, score, classification, password_length, weakness_count, created_at
            FROM analyses
            ORDER BY created_at DESC
            LIMIT 10
        """)
        recent = [dict(r) for r in cursor.fetchall()]

    return {
        "total_analyses": total_analyses,
        "average_score": avg_score,
        "classifications": classifications,
        "weakness_frequency": weaknesses,
        "length_distribution": length_distribution,
        "recent_analyses": recent
    }

def seed_demo_analytics_if_empty():
    """Seeds synthetic demo analytics so the initial dashboard has rich visualization."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analyses")
        if cursor.fetchone()[0] > 0:
            return

    # Demo synthetic dataset
    demo_samples = [
        {"score": 10, "classification": "VERY WEAK", "length": 6, "ratio": 0.5, "weakness": 4, "findings": ["common_password", "length", "sequence"]},
        {"score": 15, "classification": "VERY WEAK", "length": 6, "ratio": 0.8, "weakness": 3, "findings": ["keyboard_pattern", "length"]},
        {"score": 30, "classification": "WEAK", "length": 12, "ratio": 0.8, "weakness": 3, "findings": ["predictable_structure", "sequence"]},
        {"score": 25, "classification": "WEAK", "length": 16, "ratio": 0.1, "weakness": 2, "findings": ["repetition"]},
        {"score": 52, "classification": "MODERATE", "length": 11, "ratio": 0.9, "weakness": 1, "findings": ["length"]},
        {"score": 58, "classification": "MODERATE", "length": 12, "ratio": 0.8, "weakness": 1, "findings": ["diversity"]},
        {"score": 76, "classification": "STRONG", "length": 16, "ratio": 0.9, "weakness": 0, "findings": []},
        {"score": 88, "classification": "VERY STRONG", "length": 20, "ratio": 0.95, "weakness": 0, "findings": []},
        {"score": 95, "classification": "VERY STRONG", "length": 24, "ratio": 0.92, "weakness": 0, "findings": []}
    ]

    for item in demo_samples:
        aid = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO analyses (analysis_id, score, classification, password_length, unique_character_ratio, weakness_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (aid, item["score"], item["classification"], item["length"], item["ratio"], item["weakness"], now))
            for f in item["findings"]:
                c.execute("INSERT INTO findings (analysis_id, finding_type, severity, description) VALUES (?, ?, ?, ?)",
                          (aid, f, "medium", f.replace("_", " ").title()))
            conn.commit()
