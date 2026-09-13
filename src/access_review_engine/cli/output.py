from __future__ import annotations

from datetime import datetime
from pathlib import Path


def export_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d-%H%M")


def build_export_filename(report_name: str, extension: str, timestamp: str | None = None) -> str:
    stamp = timestamp or export_timestamp()
    clean_name = report_name.strip().strip("-")
    clean_extension = extension.lstrip(".")
    return f"{stamp}-{clean_name}.{clean_extension}"


def output_path(directory: str | Path, report_name: str, extension: str, timestamp: str) -> Path:
    return Path(directory) / build_export_filename(report_name, extension, timestamp)
