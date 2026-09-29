# Multi-stage production Dockerfile for Isihlangu: The Shield
# Stage 1: Build stage
FROM python:3.11-slim@sha256:b1d740c21ee8debe8a6ee5f27c6f09e86c0e3a6a9be8f946805607e4d8ec5b43 AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# Stage 2: Final runtime stage
FROM python:3.11-slim@sha256:b1d740c21ee8debe8a6ee5f27c6f09e86c0e3a6a9be8f946805607e4d8ec5b43 AS runtime

WORKDIR /app
COPY --from=builder /install /usr/local
COPY database/ /app/database/
COPY README.md /app/

# Create unprivileged user and data dir
RUN groupadd -r isihlangu && useradd -r -g isihlangu isihlangu && \
    mkdir -p /app/data && chown -R isihlangu:isihlangu /app

USER isihlangu

ENV PYTHONUNBUFFERED=1 \
    ISIHLANGU_DATABASE_URL=sqlite+aiosqlite:////app/data/isihlangu.db \
    ISIHLANGU_CANARY_HOST=0.0.0.0 \
    ISIHLANGU_CANARY_PORT=8877

EXPOSE 8877

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8877/health', timeout=3)" || exit 1

ENTRYPOINT ["isihlangu"]
CMD ["canary"]
