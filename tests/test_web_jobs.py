import time

from access_review_engine.web_jobs import create_job, get_job


def test_failed_job_keeps_its_provider_context(tmp_path):
    db = tmp_path / "jobs.db"

    def fail(_job_id):
        raise RuntimeError("collector failed")

    created = create_job(db, "sync", fail, context={"provider": "corp-ad"})
    job = created
    for _ in range(100):
        job = get_job(db, created["id"])
        if job["status"] == "FAILED":
            break
        time.sleep(0.01)

    assert job["status"] == "FAILED"
    assert job["result"] == {"provider": "corp-ad"}
    assert job["error"] == "The background operation failed."
