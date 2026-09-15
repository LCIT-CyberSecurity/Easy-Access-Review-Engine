FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        ldap-utils \
        zip \
    && command -v bash \
    && command -v ldapsearch \
    && command -v timeout \
    && command -v zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY exporters ./exporters
COPY scripts ./scripts
RUN pip install --no-cache-dir '.[app]'

RUN useradd --create-home --uid 10001 eare \
    && mkdir -p /data \
    && chown -R eare:eare /app /data
USER eare

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=6 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"
CMD ["uvicorn", "access_review_engine.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
