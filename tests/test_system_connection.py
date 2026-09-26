from __future__ import annotations

import threading
from pathlib import Path

from access_review_engine.api import _PerThreadConnection


def test_each_worker_thread_reads_the_system_database_on_its_own_connection(tmp_path: Path):
    shared = _PerThreadConnection(str(tmp_path / "system.db"))
    with shared:
        shared.execute("CREATE TABLE users (name TEXT)")
        shared.execute("INSERT INTO users VALUES ('admin')")
    seen: list[int] = []

    def read() -> None:
        assert shared.execute("SELECT name FROM users").fetchone()["name"] == "admin"
        seen.append(id(shared._connection()))

    workers = [threading.Thread(target=read) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert shared._connection() is shared._connection()
    assert len(set(seen)) == 4


def test_business_context_reads_tolerate_null_levels():
    from access_review_engine.api import _context_value

    assert _context_value({"business_context": {"fields": {"application": {"manual": None, "source": {"value": "CRM"}}}}}, "application", "manual") is None
    assert _context_value({"business_context": {"fields": {"application": {"source": {"value": "CRM"}}}}}, "application", "source") == "CRM"
    assert _context_value({"business_context": None}, "application", "source") is None


def test_list_summaries_count_every_filtered_row():
    from access_review_engine.web_read_models import findings_summary, list_summary

    accesses = [
        {"provider": "ldap", "holder_count": 4, "finding_count": 0},
        {"provider": "ldap", "holder_count": 3, "finding_count": 2},
        {"provider": "ad", "holder_count": 1, "finding_count": 0},
    ]
    assert list_summary("accesses", accesses) == {"total": 3, "sources": 2, "holders": 8, "with_findings": 1}
    campaigns = [{"status": "open", "pending": 5}, {"status": "closed", "pending": 0}, {"status": "draft", "pending": None}]
    assert list_summary("campaigns", campaigns) == {"total": 3, "open": 1, "closed": 1, "pending": 5}
    assert findings_summary([{"classification": "unexpected", "access_provider": "ldap"}, {"classification": "missing"}]) == {
        "total": 2, "unexpected": 1, "missing": 1, "sources": 1,
    }
