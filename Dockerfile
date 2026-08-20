# syntax=docker/dockerfile:1

# =============================================================================
# AWS Agent Identity Guard - Production Docker Image
# Multi-stage build for minimal attack surface
# =============================================================================

# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build

# Install only build-time system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency manifests first for layer caching
COPY requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy source and install the application
COPY src/ ./src/
COPY sdk/python/pyproject.toml sdk/python/setup.py ./sdk/python/
RUN pip install --no-cache-dir --prefix=/install ./sdk/python


# Stage 2: Production runtime
FROM python:3.12-slim AS runtime

# OCI image specification labels
LABEL org.opencontainers.image.title="AWS Agent Identity Guard"
LABEL org.opencontainers.image.description="Runtime authorization service for AI agents"
LABEL org.opencontainers.image.vendor="AWS Agent Identity Guard Contributors"
LABEL org.opencontainers.image.source="https://github.com/aws/agent-identity-guard"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="1.0.0"

# Security: run as non-root user
RUN groupadd --gid 1001 guard && \
    useradd --uid 1001 --gid 1001 --shell /bin/false --create-home guard

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source
WORKDIR /app
COPY --chown=guard:guard src/ ./src/
COPY --chown=guard:guard alembic.ini* ./
COPY --chown=guard:guard migrations/ ./migrations/ 2>/dev/null || true

# Remove unnecessary files to reduce attack surface
RUN find /usr/local -name '*.pyc' -delete && \
    find /usr/local -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true && \
    rm -rf /root/.cache /tmp/*

# Switch to non-root user
USER guard

# Expose the application port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Production entrypoint
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src

CMD ["python", "-m", "uvicorn", "aws_agent_identity_guard.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--access-log", "--proxy-headers"]
