"""SQLite-backed worker queue for long-running Web operations."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable
from uuid import uuid4

_WORKERS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="eare-web")

def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()

def _connect(path: str | Path) -> sqlite3.Connection:
    # A sync job is commonly queued while the page is refreshing several
    # read-model requests; tolerate that short SQLite write contention.
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS web_jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, progress TEXT NOT NULL, result TEXT, error TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS web_job_events (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, event TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL)")
    conn.commit()
    return conn

def create_job(
    db_path: str | Path,
    kind: str,
    operation: Callable[[str], dict[str, Any]],
    *,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Queue an operation and retain enough context to identify failed jobs."""
    job_id = str(uuid4())
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO web_jobs (id, kind, status, progress, result, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                job_id,
                kind,
                "QUEUED",
                "Queued",
                json.dumps(context, sort_keys=True) if context else None,
                _now(),
            ),
        )
        conn.execute("INSERT INTO web_job_events (job_id, event, detail, created_at) VALUES (?, ?, ?, ?)", (job_id, "queued", "Job queued", _now()))
    _WORKERS.submit(_run, db_path, job_id, operation)
    return get_job(db_path, job_id)

def update_progress(db_path: str | Path, job_id: str, progress: str) -> None:
    with _connect(db_path) as conn:
        conn.execute("UPDATE web_jobs SET progress = ? WHERE id = ?", (progress, job_id))
        conn.execute("INSERT INTO web_job_events (job_id, event, detail, created_at) VALUES (?, ?, ?, ?)", (job_id, "progress", progress, _now()))

def _run(db_path: str | Path, job_id: str, operation: Callable[[str], dict[str, Any]]) -> None:
    with _connect(db_path) as conn:
        conn.execute("UPDATE web_jobs SET status = ?, progress = ?, started_at = ? WHERE id = ?", ("RUNNING", "Starting", _now(), job_id))
        conn.execute("INSERT INTO web_job_events (job_id, event, detail, created_at) VALUES (?, ?, ?, ?)", (job_id, "started", "Job started", _now()))
    try:
        result = operation(job_id)
    except Exception as exc:
        with _connect(db_path) as conn:
            conn.execute("UPDATE web_jobs SET status = ?, progress = ?, error = ?, finished_at = ? WHERE id = ?", ("FAILED", "Failed", str(exc), _now(), job_id))
            conn.execute("INSERT INTO web_job_events (job_id, event, detail, created_at) VALUES (?, ?, ?, ?)", (job_id, "failed", "Job failed", _now()))
    else:
        with _connect(db_path) as conn:
            conn.execute("UPDATE web_jobs SET status = ?, progress = ?, result = ?, finished_at = ? WHERE id = ?", ("SUCCEEDED", "Completed", json.dumps(result, sort_keys=True), _now(), job_id))
            conn.execute("INSERT INTO web_job_events (job_id, event, detail, created_at) VALUES (?, ?, ?, ?)", (job_id, "completed", "Job completed", _now()))

def get_job(db_path: str | Path, job_id: str) -> dict[str, Any]:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM web_jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        raise KeyError(job_id)
    result = dict(row)
    result["result"] = json.loads(result["result"]) if result["result"] else None
    return result

def get_events(db_path: str | Path, job_id: str) -> list[dict[str, Any]]:
    with _connect(db_path) as conn:
        rows = conn.execute("SELECT event, detail, created_at FROM web_job_events WHERE job_id = ? ORDER BY id", (job_id,)).fetchall()
    return [dict(row) for row in rows]
