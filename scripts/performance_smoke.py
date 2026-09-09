from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path
import resource
import tempfile
import time
from zipfile import ZIP_DEFLATED, ZipFile

from access_review_engine.application import import_file_to_repository
from access_review_engine.services import create_golden_source, promote_snapshot
from access_review_engine.storage import Repository


def main() -> int:
    identities = 10_000
    groups = 2_000
    assignments = 100_000
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        archive = _ad_zip(base, identities, groups, assignments)
        db = base / "performance.db"
        repo = Repository(db)
        try:
            started = time.perf_counter()
            snapshot = import_file_to_repository(repo, archive)
            imported = time.perf_counter()
            golden = promote_snapshot(create_golden_source("perf"), snapshot)
            promoted = time.perf_counter()
            rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            print(f"identities={identities}")
            print(f"groups={groups}")
            print(f"assignments={assignments}")
            print(f"import_seconds={imported - started:.3f}")
            print(f"promote_seconds={promoted - imported:.3f}")
            print(f"db_bytes={db.stat().st_size}")
            print(f"max_rss_kb={rss_kb}")
            print(f"golden_assignments={len(golden.assignments)}")
        finally:
            repo.close()
    return 0


def _ad_zip(base: Path, identities: int, groups: int, assignments: int) -> Path:
    archive = base / "performance-ad.zip"
    domain = "S-1-5-21-10-20-30"
    users = [
        {
            "SamAccountName": f"user{i:05d}",
            "Enabled": "true",
            "SID": f"{domain}-{100000 + i}",
            "DistinguishedName": f"CN=user{i:05d},OU=Users,DC=perf,DC=test",
            "PrimaryGroupID": "513",
        }
        for i in range(identities)
    ]
    group_rows = [
        {
            "SamAccountName": f"GG_{i:05d}",
            "Name": f"GG_{i:05d}",
            "SID": f"{domain}-{200000 + i}",
            "DistinguishedName": f"CN=GG_{i:05d},OU=Groups,DC=perf,DC=test",
            "GroupScope": "Global",
            "GroupCategory": "Security",
        }
        for i in range(groups)
    ]
    membership_rows = []
    for i in range(assignments):
        user_index = i % identities
        group_index = (i + (i // identities) * 137) % groups
        membership_rows.append(
            {
                "Group": f"GG_{group_index:05d}",
                "GroupSID": f"{domain}-{200000 + group_index}",
                "Member": f"user{user_index:05d}",
                "MemberSID": f"{domain}-{100000 + user_index}",
                "MemberType": "user",
                "MemberDN": f"CN=user{user_index:05d},OU=Users,DC=perf,DC=test",
                "MembershipType": "direct",
            }
        )
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        zf.writestr("manifest.yaml", "schema_version: 1\nsource_type: active_directory\nprovider: perf-ad\ncompleteness: full\nstatistics:\n  collection_errors: 0\n")
        zf.writestr("users.csv", _csv(list(users[0]), users))
        zf.writestr("groups.csv", _csv(list(group_rows[0]), group_rows))
        zf.writestr("memberships.csv", _csv(list(membership_rows[0]), membership_rows))
        zf.writestr("service_accounts.csv", "SamAccountName,SID,DistinguishedName,Enabled,ObjectClass,PrimaryGroupID\n")
        zf.writestr("computers.csv", "SamAccountName,Name,SID,DistinguishedName,Enabled,DNSHostName,Description,ObjectGUID,PrimaryGroupID\n")
        zf.writestr("collection-errors.csv", "ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage\n")
    return archive


def _csv(fieldnames: list[str], rows: list[dict[str, str]]) -> str:
    stream = StringIO()
    writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
