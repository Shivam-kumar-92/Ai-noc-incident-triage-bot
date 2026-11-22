"""SQLite persistence layer for AI-triaged incidents and token-efficiency metrics."""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator

from .models import RCAReport


class IncidentStore:
    """Thread-safe SQLite store for AI RCA reports and Tier-1 token savings."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path.resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS rca_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    osi_layer TEXT NOT NULL,
                    category TEXT NOT NULL,
                    target TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    blast_radius TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    remediation_json TEXT NOT NULL,
                    verification_json TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    engine_used TEXT NOT NULL,
                    prompt_tokens_est INTEGER NOT NULL,
                    raw_tokens_avoided_est INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_rca_ts ON rca_incidents (timestamp_utc DESC);
                """
            )

    def save_report(self, report: RCAReport) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rca_incidents (
                    incident_id, timestamp_utc, title, severity, osi_layer, category,
                    target, root_cause, blast_radius, evidence_json, remediation_json,
                    verification_json, confidence, engine_used, prompt_tokens_est,
                    raw_tokens_avoided_est
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.incident_id,
                    report.timestamp_utc,
                    report.title,
                    report.severity,
                    report.osi_layer,
                    report.category,
                    report.target,
                    report.root_cause,
                    report.blast_radius,
                    json.dumps(list(report.evidence)),
                    json.dumps(list(report.remediation_steps)),
                    json.dumps(list(report.verification_commands)),
                    report.confidence,
                    report.engine_used,
                    report.prompt_tokens_est,
                    report.raw_tokens_avoided_est,
                ),
            )

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM rca_incidents ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d.pop("evidence_json"))
            d["remediation_steps"] = json.loads(d.pop("remediation_json"))
            d["verification_commands"] = json.loads(d.pop("verification_json"))
            items.append(d)
        return items

    def get_metrics(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_incidents,
                    SUM(CASE WHEN severity = 'SEV-1' THEN 1 ELSE 0 END) AS sev1_count,
                    SUM(CASE WHEN severity = 'SEV-2' THEN 1 ELSE 0 END) AS sev2_count,
                    COALESCE(SUM(prompt_tokens_est), 0) AS total_prompt_tokens,
                    COALESCE(SUM(raw_tokens_avoided_est), 0) AS total_tokens_saved
                FROM rca_incidents
                """
            ).fetchone()
        prompt_t = int(row["total_prompt_tokens"])
        saved_t = int(row["total_tokens_saved"])
        denom = prompt_t + saved_t
        savings_pct = round((saved_t / denom) * 100.0, 1) if denom > 0 else 0.0
        return {
            "total_incidents": int(row["total_incidents"]),
            "sev1_count": int(row["sev1_count"] or 0),
            "sev2_count": int(row["sev2_count"] or 0),
            "total_prompt_tokens": prompt_t,
            "total_tokens_saved": saved_t,
            "token_savings_pct": savings_pct,
        }
