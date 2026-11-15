from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_application_images_keep_debian_13_build_targets_and_alpine_runtime() -> None:
    backend = (ROOT / "docker/backend.Dockerfile").read_text(encoding="utf-8")
    frontend = (ROOT / "web/Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.12-slim-trixie" in backend
    assert "FROM node:22-trixie AS build" in frontend
    assert "FROM nginx:1.27-alpine" in frontend
