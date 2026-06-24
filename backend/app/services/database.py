"""SQLite database service for storing analysis results."""

import json
import sqlite3
import os
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "threat_intel.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            input_text TEXT NOT NULL,
            input_type TEXT NOT NULL,
            result_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_analysis(analysis_id: str, timestamp: str, input_text: str, input_type: str, result: dict):
    """Save analysis result to database."""
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO analyses (analysis_id, timestamp, input_text, input_type, result_json) VALUES (?, ?, ?, ?, ?)",
        (analysis_id, timestamp, input_text, input_type, json.dumps(result)),
    )
    conn.commit()
    conn.close()


def get_analysis(analysis_id: str) -> Optional[dict]:
    """Get a single analysis by ID."""
    conn = get_connection()
    row = conn.execute("SELECT result_json FROM analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
    conn.close()
    if row:
        return json.loads(row["result_json"])
    return None


def get_analyses(page: int = 1, page_size: int = 20) -> tuple[list[dict], int]:
    """Get paginated analysis history."""
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as cnt FROM analyses").fetchone()["cnt"]
    offset = (page - 1) * page_size
    rows = conn.execute(
        "SELECT result_json FROM analyses ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (page_size, offset),
    ).fetchall()
    conn.close()
    return [json.loads(r["result_json"]) for r in rows], total
