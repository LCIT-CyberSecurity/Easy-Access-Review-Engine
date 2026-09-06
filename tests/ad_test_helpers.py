from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def zip_fixture(tmp_path: Path, fixture_name: str) -> Path:
    source = Path("fixtures/raw/active-directory") / fixture_name
    archive = tmp_path / f"{fixture_name}.zip"
    with ZipFile(archive, "w", ZIP_DEFLATED) as zf:
        for item in sorted(source.iterdir()):
            if item.is_file():
                zf.write(item, item.name)
    return archive
